var index = (() => {
  const {Plugin, Dialog, Menu, showMessage, confirm, fetchSyncPost, getAllEditor, getFrontend} = require("siyuan");

  const PREFIX = "enc:v1:";
  const SUPPORTED_TYPES = ["p", "h1", "h2", "h3", "h4", "h5", "h6", "li", "blockquote"];
  const ENCRYPTED_ATTR = "custom-encrypted";
  const ENCRYPTED_VALUE = "🔒 已加密";
  const PAYLOAD_RE = /enc:v1:[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+/g;

  function bufToB64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  }

  function b64ToBuf(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function isMobile() {
    const f = getFrontend();
    return f === "mobile" || f === "browser-mobile";
  }

  async function deriveKey(password, salt) {
    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256"},
      material,
      {name: "AES-GCM", length: 256},
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptText(password, text) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        {name: "AES-GCM", iv},
        key,
        new TextEncoder().encode(text)
      )
    );
    return PREFIX + bufToB64(salt) + "." + bufToB64(iv) + "." + bufToB64(ct);
  }

  async function decryptText(password, payload) {
    if (!payload.startsWith(PREFIX)) {
      throw new Error("not-encrypted");
    }
    const parts = payload.slice(PREFIX.length).split(".");
    if (parts.length !== 3) {
      throw new Error("bad-format");
    }
    const key = await deriveKey(password, b64ToBuf(parts[0]));
    const plain = await crypto.subtle.decrypt(
      {name: "AES-GCM", iv: b64ToBuf(parts[1])},
      key,
      b64ToBuf(parts[2])
    );
    return new TextDecoder().decode(plain);
  }

  function extractPayloads(text) {
    PAYLOAD_RE.lastIndex = 0;
    return text.match(PAYLOAD_RE) || [];
  }

  async function post(url, data) {
    const res = await fetchSyncPost(url, data);
    if (res && res.code === 0) {
      return res.data;
    }
    throw new Error((res && res.msg) || "request failed: " + url);
  }

  const setBlockAttr = (id, name, value) => post("/api/attr/setBlockAttrs", {id, attrs: {[name]: value}});

  class TextEncryptPlugin extends Plugin {
    onload() {
      this.contentMenuHandler = this.contentMenuHandler.bind(this);
      this.eventBus.on("open-menu-content", this.contentMenuHandler);
      this.addTopBar({
        icon: "iconLock",
        title: "文本加密",
        position: "right",
        callback: (event) => this.showTopBarMenu(event),
      });
      console.log("[text-encrypt] loaded");
    }

    onunload() {
      this.eventBus.off("open-menu-content", this.contentMenuHandler);
    }

    contentMenuHandler({detail}) {
      const {menu, range, protyle} = detail || {};
      if (!menu || !range || range.collapsed) {
        return;
      }
      const selText = range.toString();
      if (!selText.trim()) {
        return;
      }
      const hasEncrypted = selText.includes(PREFIX);
      const submenu = [];
      if (hasEncrypted) {
        submenu.push({
          icon: "iconUnlock",
          label: "解密查看",
          click: () => this.decryptSelection(range, protyle),
        });
      } else {
        submenu.push({
          icon: "iconLock",
          label: "设置加密",
          click: () => this.encryptSelection(range, protyle),
        });
      }
      menu.addItem({
        icon: "iconLock",
        label: "加密",
        type: "submenu",
        submenu,
      });
    }

    showTopBarMenu(event) {
      const menu = new Menu("text-encrypt-topbar", () => {});
      menu.addItem({
        icon: "iconLock",
        label: "加密选中文本",
        click: () => this.encryptCurrentSelection(),
      });
      menu.addItem({
        icon: "iconUnlock",
        label: "解密查看选中文本",
        click: () => this.decryptCurrentSelection(),
      });
      if (isMobile()) {
        menu.fullscreen();
      } else if (event && event.clientX !== undefined) {
        menu.open({x: event.clientX, y: event.clientY});
      } else {
        menu.fullscreen();
      }
    }

    getActiveProtyle() {
      const editors = getAllEditor();
      return editors && editors.length > 0 ? editors[0] : null;
    }

    getCurrentRange() {
      const sel = window.getSelection();
      if (!sel || sel.rangeCount === 0 || sel.getRangeAt(0).collapsed) {
        return null;
      }
      return sel.getRangeAt(0);
    }

    encryptCurrentSelection() {
      const range = this.getCurrentRange();
      if (!range) {
        showMessage("请先选中要加密的文本", 3000, "error");
        return;
      }
      this.encryptSelection(range, this.getActiveProtyle());
    }

    decryptCurrentSelection() {
      const range = this.getCurrentRange();
      if (!range) {
        showMessage("请先选中要解密的文本", 3000, "error");
        return;
      }
      this.decryptSelection(range, this.getActiveProtyle());
    }

    getWysiwyg(protyle) {
      if (protyle && protyle.wysiwyg && protyle.wysiwyg.element) {
        return protyle.wysiwyg.element;
      }
      return document.querySelector(".protyle-wysiwyg");
    }

    getBlocksInRange(range, protyle) {
      const results = [];
      const root = this.getWysiwyg(protyle);
      if (!root) {
        return results;
      }
      root.querySelectorAll("[data-node-id]").forEach((el) => {
        const id = el.dataset.nodeId;
        if (!id) {
          return;
        }
        const blockRange = document.createRange();
        blockRange.selectNodeContents(el);
        try {
          const startIn = this.isPointInElement(range.startContainer, el);
          const endIn = this.isPointInElement(range.endContainer, el);
          const full =
            range.compareBoundaryPoints(Range.START_TO_START, blockRange) <= 0 &&
            range.compareBoundaryPoints(Range.END_TO_END, blockRange) >= 0;
          const intersects =
            range.compareBoundaryPoints(Range.START_TO_END, blockRange) > 0 &&
            range.compareBoundaryPoints(Range.END_TO_START, blockRange) < 0;
          if (!intersects) {
            return;
          }
          let partialText = null;
          if (!full) {
            const r = range.cloneRange();
            if (!startIn) {
              r.setStart(blockRange.startContainer, blockRange.startOffset);
            }
            if (!endIn) {
              r.setEnd(blockRange.endContainer, blockRange.endOffset);
            }
            partialText = r.toString();
          }
          const text = this.getBlockText(el);
          if (text === null) {
            return;
          }
          results.push({
            id,
            element: el,
            type: this.getBlockType(el),
            full,
            partialText,
            text,
          });
        } catch (e) {
          console.error("[text-encrypt]", e);
        }
      });
      return results;
    }

    // 只取块自身的可编辑文本，避免把子块的文字误当成父块文字
    getOwnEdit(el) {
      const edits = el.querySelectorAll('[contenteditable="true"]');
      for (const edit of edits) {
        if (edit.closest('[data-node-id]') === el) {
          return edit;
        }
      }
      return null;
    }

    getBlockText(el) {
      const edit = this.getOwnEdit(el);
      if (!edit) {
        return null;
      }
      return edit.innerText.replace(/\u200B/g, "");
    }

    getBlockType(el) {
      const t = el.getAttribute("data-type") || "";
      const cls = el.className || "";
      if (t === "NodeParagraph") {
        return "p";
      }
      if (t === "NodeListItem") {
        return "li";
      }
      if (t === "NodeBlockquote") {
        return "blockquote";
      }
      if (t === "NodeHeading") {
        const m = cls.match(/\b(h[1-6])\b/);
        return m ? m[1] : "h1";
      }
      return "";
    }

    isPointInElement(container, el) {
      const node = container.nodeType === Node.TEXT_NODE ? container.parentElement : container;
      return node && el.contains(node);
    }

    transactionUpdate(protyle, doOperations) {
      const instance = protyle && protyle.getInstance ? protyle.getInstance() : null;
      if (!instance || !instance.transaction) {
        return false;
      }
      instance.transaction(doOperations);
      return true;
    }

    dialogWidth(mobile, desktop) {
      return isMobile() ? mobile : desktop;
    }

    copyText(text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text);
      }
      return new Promise((resolve, reject) => {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        try {
          document.execCommand("copy");
          resolve();
        } catch (e) {
          reject(e);
        }
        document.body.removeChild(ta);
      });
    }

    async encryptSelection(range, protyle) {
      const blocks = this.getBlocksInRange(range, protyle).filter((b) => SUPPORTED_TYPES.includes(b.type));
      if (blocks.length === 0) {
        showMessage("所选区域没有可加密的文本块", 3000, "error");
        return;
      }

      const dialog = new Dialog({
        title: "设置加密",
        content: `<div class="b3-dialog__content">
  <div class="b3-typography" style="margin-bottom:12px;">将为选中内容设置加密密码，共涉及 ${blocks.length} 个块。<br>请牢记密码，忘记后无法找回。</div>
  <input class="b3-text-field fn__block" id="encPwd1" type="password" placeholder="请输入加密密码">
  <input class="b3-text-field fn__block" id="encPwd2" type="password" placeholder="请再次输入密码" style="margin-top:8px;">
</div>
<div class="b3-dialog__action">
  <button class="b3-button b3-button--cancel" id="encCancel">取消</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--text" id="encOk">加密</button>
</div>`,
        width: this.dialogWidth("92vw", "480px"),
      });

      const input1 = dialog.element.querySelector("#encPwd1");
      const input2 = dialog.element.querySelector("#encPwd2");
      const okBtn = dialog.element.querySelector("#encOk");
      const cancelBtn = dialog.element.querySelector("#encCancel");

      cancelBtn.addEventListener("click", () => dialog.destroy());
      okBtn.addEventListener("click", async () => {
        const pwd = input1.value;
        if (!pwd) {
          showMessage("请输入密码", 3000, "error");
          return;
        }
        if (pwd !== input2.value) {
          showMessage("两次输入的密码不一致", 3000, "error");
          return;
        }
        dialog.destroy();
        let okCount = 0;
        let skippedCount = 0;
        try {
          const ordered = blocks.slice().reverse();
          for (const b of ordered) {
            const r = await this.encryptOneBlock(b, pwd, protyle);
            if (r === "ok") {
              okCount++;
            } else {
              skippedCount++;
            }
          }
          if (okCount > 0) {
            showMessage("已加密 " + okCount + " 个块" + (skippedCount > 0 ? "，跳过 " + skippedCount + " 个" : ""));
          } else {
            showMessage("没有可加密的内容（已加密或无法定位选中文本）", 4000, "error");
          }
        } catch (e) {
          console.error("[text-encrypt]", e);
          showMessage("加密失败：" + e.message, 5000, "error");
        }
      });
      dialog.bindInput(input2, () => okBtn.click());
      input1.focus();
    }

    async encryptOneBlock(blockInfo, password, protyle) {
      const {id, element, full, partialText, text} = blockInfo;
      if (!text || !text.trim()) {
        return "empty";
      }
      if (text.includes(PREFIX)) {
        return "already";
      }
      let textToEncrypt = null;
      let idx = -1;
      if (full) {
        textToEncrypt = text;
      } else if (partialText) {
        idx = text.indexOf(partialText);
        if (idx === -1) {
          return "not-found";
        }
        textToEncrypt = partialText;
      } else {
        return "no-selection";
      }
      const ct = await encryptText(password, textToEncrypt);
      const edit = this.getOwnEdit(element);
      if (!edit) {
        return "no-editable";
      }
      if (full) {
        edit.textContent = ct;
      } else {
        const before = escapeHtml(text.slice(0, idx));
        const after = escapeHtml(text.slice(idx + textToEncrypt.length));
        edit.innerHTML = before + '<span data-type="code">' + escapeHtml(ct) + '</span>' + after;
      }
      if (!this.transactionUpdate(protyle, [{action: "update", id, data: element.outerHTML}])) {
        return "no-protyle";
      }
      await setBlockAttr(id, ENCRYPTED_ATTR, ENCRYPTED_VALUE);
      return "ok";
    }

    async decryptSelection(range, protyle) {
      const blocks = this.getBlocksInRange(range, protyle);
      const targets = [];
      for (const b of blocks) {
        const payloads = extractPayloads(b.text || "");
        if (payloads.length > 0) {
          targets.push({id: b.id, element: b.element, text: b.text, payloads});
        }
      }
      if (targets.length === 0) {
        showMessage("所选内容中未找到加密文本", 3000, "error");
        return;
      }

      const dialog = new Dialog({
        title: "解密查看",
        content: `<div class="b3-dialog__content">
  <div class="b3-typography" style="margin-bottom:12px;">输入加密时设置的密码以查看明文。</div>
  <input class="b3-text-field fn__block" id="decPwd" type="password" placeholder="请输入加密密码">
</div>
<div class="b3-dialog__action">
  <button class="b3-button b3-button--cancel" id="decCancel">取消</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--text" id="decOk">查看</button>
</div>`,
        width: this.dialogWidth("92vw", "480px"),
      });

      const pwdInput = dialog.element.querySelector("#decPwd");
      const okBtn = dialog.element.querySelector("#decOk");
      const cancelBtn = dialog.element.querySelector("#decCancel");

      cancelBtn.addEventListener("click", () => dialog.destroy());
      okBtn.addEventListener("click", async () => {
        const pwd = pwdInput.value;
        if (!pwd) {
          showMessage("请输入密码", 3000, "error");
          return;
        }
        const plainParts = [];
        try {
          for (const t of targets) {
            for (const payload of t.payloads) {
              plainParts.push(await decryptText(pwd, payload));
            }
          }
        } catch (e) {
          showMessage("密码错误或密文已损坏", 5000, "error");
          return;
        }
        let plainIdx = 0;
        const restored = targets.map((t) => ({
          id: t.id,
          element: t.element,
          text: t.text,
          pairs: t.payloads.map((payload) => ({
            payload,
            plain: plainParts[plainIdx++],
          })),
        }));
        dialog.destroy();
        this.showPlainDialog(restored, plainParts.join("\n\n"), protyle);
      });
      dialog.bindInput(pwdInput, () => okBtn.click());
      pwdInput.focus();
    }

    showPlainDialog(restored, plain, protyle) {
      const resultDialog = new Dialog({
        title: "解密内容",
        content: `<div class="b3-dialog__content">
  <textarea class="b3-text-field fn__block" id="decPlain" readonly style="height:220px;">${escapeHtml(plain)}</textarea>
</div>
<div class="b3-dialog__action">
  <button class="b3-button b3-button--cancel" id="decClose">关闭</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--outline" id="decCopy">复制</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--text" id="decRestore">解密并恢复为明文（移除加密）</button>
</div>`,
        width: this.dialogWidth("92vw", "640px"),
      });

      resultDialog.element.querySelector("#decClose").addEventListener("click", () => resultDialog.destroy());
      resultDialog.element.querySelector("#decCopy").addEventListener("click", () => {
        this.copyText(plain).then(() => {
          showMessage("已复制明文");
        }).catch(() => {
          showMessage("复制失败，请长按文本手动复制", 3000, "error");
        });
      });
      resultDialog.element.querySelector("#decRestore").addEventListener("click", () => {
        confirm("恢复明文", "将把所选块恢复为明文并移除加密标记，确定？", async () => {
          try {
            const ops = [];
            for (const t of restored) {
              let newText = t.text;
              for (const pair of t.pairs) {
                newText = newText.split(pair.payload).join(pair.plain);
              }
              const root = this.getWysiwyg(protyle);
              const el = root ? root.querySelector('div[data-node-id="' + t.id + '"]') : null;
              if (el) {
                const edit = this.getOwnEdit(el);
                if (edit) {
                  edit.textContent = newText;
                  ops.push({action: "update", id: t.id, data: el.outerHTML});
                }
              }
            }
            if (ops.length > 0) {
              this.transactionUpdate(protyle, ops);
            }
            for (const t of restored) {
              await setBlockAttr(t.id, ENCRYPTED_ATTR, "");
            }
            showMessage("已恢复为明文");
            resultDialog.destroy();
          } catch (e) {
            console.error("[text-encrypt]", e);
            showMessage("恢复失败：" + e.message, 5000, "error");
          }
        });
      });
    }
  }

  module.exports = {default: TextEncryptPlugin};
  return module.exports;
})();
