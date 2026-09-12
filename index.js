var index = (() => {
  const {Plugin, Dialog, Menu, showMessage, confirm, fetchSyncPost, getAllEditor, getFrontend, platformUtils} = require("siyuan");

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
      // 记住最近一次非折叠选区：移动端点击工具栏可能先清空选区
      this.lastRange = null;
      this.rememberSelection = () => {
        try {
          const sel = window.getSelection();
          if (sel && sel.rangeCount > 0 && !sel.getRangeAt(0).collapsed) {
            this.lastRange = sel.getRangeAt(0).cloneRange();
          }
        } catch (e) {
          /* ignore */
        }
      };
      document.addEventListener("selectionchange", this.rememberSelection);
      this.addTopBar({
        icon: "iconLock",
        title: "文本加密",
        position: "right",
        callback: (event) => this.showTopBarMenu(event),
      });
      // 3.8+ 选择工具栏入口（移动端主要入口，避免选中文字后选区丢失）
      this.hasToolbarApi = false;
      if (typeof this.addToolbarItem === "function") {
        try {
          this.addToolbarItem({
            name: "text-encrypt",
            icon: "iconLock",
            tip: "文本加密",
            tipPosition: "n",
            click: (protyle) => this.onToolbarClick(protyle),
          });
          this.hasToolbarApi = true;
        } catch (e) {
          console.error("[text-encrypt] addToolbarItem failed", e);
        }
      }
      console.log("[text-encrypt] loaded");
    }

    // 旧版本（3.8 之前）回退：把入口加进编辑器工具栏
    updateProtyleToolbar(toolbar) {
      if (this.hasToolbarApi) {
        return toolbar;
      }
      toolbar.push({
        name: "text-encrypt",
        icon: "iconLock",
        tip: "文本加密",
        tipPosition: "n",
        click: (protyle) => this.onToolbarClick(protyle),
      });
      return toolbar;
    }

    // 选择工具栏按钮：按选区内容自动决定加密还是解密
    onToolbarClick(ctx) {
      const range = this.getCurrentRange();
      if (!range) {
        showMessage("请先选中要加密或解密的文本", 3000, "error");
        return;
      }
      const protyle = this.getProtyleForRange(range) || this.unwrapProtyle(ctx);
      const selText = range.toString();
      if (selText.includes(PREFIX)) {
        this.decryptSelection(range, protyle);
      } else {
        this.encryptSelection(range, protyle);
      }
    }

    // 3.8 起插件命令/工具栏回调传入统一执行上下文（含 protyle 字段），这里做兼容解包
    unwrapProtyle(ctx) {
      if (ctx && ctx.protyle && ctx.protyle.wysiwyg) {
        return ctx.protyle;
      }
      return ctx;
    }

    onunload() {
      this.eventBus.off("open-menu-content", this.contentMenuHandler);
      if (this.rememberSelection) {
        document.removeEventListener("selectionchange", this.rememberSelection);
      }
    }

    contentMenuHandler({detail}) {
      const {menu, range, protyle} = detail || {};
      if (!menu) {
        return;
      }
      const target = this.resolveMenuTarget(range, protyle);
      if (!target) {
        return;
      }
      const submenu = [];
      if (target.hasEncrypted) {
        submenu.push({
          icon: "iconUnlock",
          label: "解密查看",
          click: () => this.decryptSelection(target.range, protyle),
        });
      } else {
        submenu.push({
          icon: "iconLock",
          label: "设置加密",
          click: () => this.encryptSelection(target.range, protyle),
        });
      }
      menu.addItem({
        icon: "iconLock",
        label: "加密",
        type: "submenu",
        submenu,
      });
    }

    // 判断右键菜单应提供加密还是解密：兼容移动端选区文本取不到代码片段的情况
    resolveMenuTarget(range, protyle) {
      try {
        if (range && !range.collapsed) {
          const selText = String(range.toString());
          if (selText.includes(PREFIX) || this.rangeHasCipherCode(range)) {
            return {range, hasEncrypted: true};
          }
          const blocks = this.getBlocksInRange(range, protyle);
          if (blocks.some((b) => (b.text || "").includes(PREFIX))) {
            return {range, hasEncrypted: true};
          }
          if (selText.trim()) {
            return {range, hasEncrypted: false};
          }
        }
        // 折叠光标 / 无选区：所在块含密文时允许解密整块
        const block = this.getBlockElementAt(range, protyle);
        if (block && (this.getBlockText(block) || "").includes(PREFIX)) {
          const edit = this.getOwnEdit(block);
          if (edit) {
            const r = document.createRange();
            r.selectNodeContents(edit);
            return {range: r, hasEncrypted: true};
          }
        }
      } catch (e) {
        console.error("[text-encrypt]", e);
      }
      return null;
    }

    rangeHasCipherCode(range) {
      try {
        const frag = range.cloneContents();
        const codes = frag && frag.querySelectorAll ? Array.from(frag.querySelectorAll('span[data-type="code"]')) : [];
        return codes.some((c) => (c.textContent || "").includes(PREFIX));
      } catch (e) {
        return false;
      }
    }

    getBlockElementAt(range, protyle) {
      let node = range && range.startContainer ? range.startContainer : null;
      if (!node) {
        const sel = window.getSelection();
        node = sel && sel.anchorNode ? sel.anchorNode : null;
      }
      if (!node) {
        return null;
      }
      const el = node.nodeType === Node.TEXT_NODE ? node.parentElement : node;
      if (!el || !el.closest) {
        return null;
      }
      const block = el.closest("[data-node-id]");
      if (!block) {
        return null;
      }
      const root = this.resolveRoot(range, protyle);
      return root && !root.contains(block) ? null : block;
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

    // 找到选区所在编辑器（避免取到隐藏页签导致“没有可加密的文本块”）
    getProtyleForRange(range) {
      try {
        const editors = getAllEditor() || [];
        for (const editor of editors) {
          const el = editor && editor.wysiwyg && editor.wysiwyg.element;
          if (el && range && el.contains(range.startContainer)) {
            return editor;
          }
        }
        return editors.length > 0 ? editors[0] : null;
      } catch (e) {
        console.error("[text-encrypt]", e);
        return null;
      }
    }

    // 解析可用的编辑器对象：传入的优先，其次按选区查找
    resolveEditor(range, protyle) {
      const p = this.unwrapProtyle(protyle);
      if (p && p.wysiwyg && p.wysiwyg.element && (!range || p.wysiwyg.element.contains(range.startContainer))) {
        return p;
      }
      return this.getProtyleForRange(range) || p || null;
    }

    getCurrentRange() {
      const sel = window.getSelection();
      if (sel && sel.rangeCount > 0 && !sel.getRangeAt(0).collapsed) {
        return sel.getRangeAt(0);
      }
      // 移动端点击工具栏后选区可能被清空，回退到最近一次有效选区
      const last = this.lastRange;
      if (last && last.startContainer && last.startContainer.isConnected && !last.collapsed) {
        return typeof last.cloneRange === "function" ? last.cloneRange() : last;
      }
      return null;
    }

    encryptCurrentSelection() {
      const range = this.getCurrentRange();
      if (!range) {
        showMessage("请先选中要加密的文本", 3000, "error");
        return;
      }
      this.encryptSelection(range, this.getProtyleForRange(range));
    }

    decryptCurrentSelection() {
      const range = this.getCurrentRange();
      if (!range) {
        showMessage("请先选中要解密的文本", 3000, "error");
        return;
      }
      this.decryptSelection(range, this.getProtyleForRange(range));
    }

    getWysiwyg(protyle) {
      const p = this.unwrapProtyle(protyle);
      if (p && p.wysiwyg && p.wysiwyg.element) {
        return p.wysiwyg.element;
      }
      return document.querySelector(".protyle-wysiwyg");
    }

    getBlocksInRange(range, protyle) {
      const results = [];
      const root = this.resolveRoot(range, protyle);
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

    // 找到真正包含选区的编辑器根元素（避免命中隐藏页签）
    resolveRoot(range, protyle) {
      const p = this.unwrapProtyle(protyle);
      const fromProtyle = p && p.wysiwyg && p.wysiwyg.element;
      if (fromProtyle && (!range || fromProtyle.contains(range.startContainer))) {
        return fromProtyle;
      }
      const all = Array.from(document.querySelectorAll(".protyle-wysiwyg"));
      if (range) {
        const hit = all.find((el) => el.contains(range.startContainer));
        if (hit) {
          return hit;
        }
      }
      return fromProtyle || all[0] || null;
    }

    // 跨编辑器按块 ID 定位元素
    findBlockElement(id, protyle) {
      const p = this.unwrapProtyle(protyle);
      const preferred = p && p.wysiwyg && p.wysiwyg.element;
      if (preferred) {
        const el = preferred.querySelector('div[data-node-id="' + id + '"]');
        if (el) {
          return { el, root: preferred };
        }
      }
      const all = Array.from(document.querySelectorAll(".protyle-wysiwyg"));
      for (const root of all) {
        const el = root.querySelector('div[data-node-id="' + id + '"]');
        if (el) {
          return { el, root };
        }
      }
      return null;
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
      if (!protyle) {
        return false;
      }
      try {
        const p = this.unwrapProtyle(protyle);
        const instance = typeof p.getInstance === "function" ? p.getInstance() : p;
        if (instance && typeof instance.transaction === "function") {
          instance.transaction(doOperations);
          return true;
        }
      } catch (e) {
        console.error("[text-encrypt]", e);
      }
      return false;
    }

    dialogWidth(mobile, desktop) {
      return isMobile() ? mobile : desktop;
    }

    // 移动端键盘适配：键盘弹出时把弹窗顶到可视区域内并限制高度
    assistKeyboard(dialog) {
      if (!isMobile() || !dialog || !dialog.element) {
        return;
      }
      const root = dialog.element;
      const panel = root.querySelector(".b3-dialog__container");
      if (!panel) {
        return;
      }
      const adjust = () => {
        try {
          const vv = window.visualViewport;
          const visible = vv ? vv.height : window.innerHeight;
          const top = vv ? vv.offsetTop : 0;
          const active = document.activeElement;
          const editing = !!active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA");
          root.classList.toggle("text-encrypt-dialog--keyboard", editing);
          panel.style.maxHeight = Math.max(240, visible - 24) + "px";
          panel.style.marginTop = editing ? top + 8 + "px" : "";
        } catch (e) {
          console.error("[text-encrypt]", e);
        }
      };
      const onFocusIn = () => setTimeout(adjust, 260);
      const onFocusOut = () => setTimeout(adjust, 60);
      const onResize = () => adjust();
      root.addEventListener("focusin", onFocusIn);
      root.addEventListener("focusout", onFocusOut);
      if (window.visualViewport) {
        window.visualViewport.addEventListener("resize", onResize);
        window.visualViewport.addEventListener("scroll", onResize);
      }
      adjust();
      const origDestroy = dialog.destroy.bind(dialog);
      dialog.destroy = (...args) => {
        root.removeEventListener("focusin", onFocusIn);
        root.removeEventListener("focusout", onFocusOut);
        if (window.visualViewport) {
          window.visualViewport.removeEventListener("resize", onResize);
          window.visualViewport.removeEventListener("scroll", onResize);
        }
        return origDestroy(...args);
      };
    }

    // 移动端自动聚焦可能失败，延迟 + 失焦编辑器后重试；点击弹窗空白处也可唤起键盘
    focusInput(input) {
      if (!input) {
        return;
      }
      const isFocused = () => document.activeElement === input;
      const attempt = () => {
        if (isFocused()) {
          return true;
        }
        try {
          const active = document.activeElement;
          if (active && active !== input && typeof active.blur === "function") {
            active.blur();
          }
          input.focus();
          if (typeof input.setSelectionRange === "function") {
            try {
              input.setSelectionRange(input.value.length, input.value.length);
            } catch (e) {
              /* 某些输入类型不支持 setSelectionRange */
            }
          }
        } catch (e) {
          console.error("[text-encrypt]", e);
        }
        return isFocused();
      };
      // 立即尝试：保留用户手势上下文，移动端键盘更易弹出
      attempt();
      if (!isMobile()) {
        return;
      }
      // 菜单关闭时编辑器可能抢回焦点，这里多次重试直到聚焦成功
      [80, 200, 400, 700, 1100].forEach((delay) => setTimeout(() => attempt(), delay));
    }

    // 弹窗刚打开的一小段时间内防止焦点被编辑器抢走（否则键盘会立刻收起）
    guardFocus(dialog, input) {
      if (!isMobile() || !dialog || !dialog.element) {
        return;
      }
      const startedAt = Date.now();
      const onFocusIn = () => {
        if (Date.now() - startedAt > 3000) {
          return;
        }
        setTimeout(() => {
          try {
            if (!document.body.contains(dialog.element)) {
              return;
            }
            const active = document.activeElement;
            if (active && dialog.element.contains(active)) {
              return;
            }
            input.focus();
          } catch (e) {
            console.error("[text-encrypt]", e);
          }
        }, 50);
      };
      document.addEventListener("focusin", onFocusIn, true);
      const origDestroy = dialog.destroy.bind(dialog);
      dialog.destroy = (...args) => {
        document.removeEventListener("focusin", onFocusIn, true);
        return origDestroy(...args);
      };
    }

    bindDialogTapFocus(dialog, inputs) {
      if (!isMobile() || !dialog || !dialog.element) {
        return;
      }
      const body = dialog.element.querySelector(".b3-dialog__content") || dialog.element;
      body.addEventListener("click", (e) => {
        const t = e.target;
        if (!t) {
          return;
        }
        const tag = t.tagName;
        if (tag === "INPUT" || tag === "TEXTAREA" || tag === "BUTTON" || (t.closest && t.closest("button"))) {
          return;
        }
        const target = inputs.find((i) => i && !i.value) || inputs[0];
        this.focusInput(target);
      });
    }

    copyText(text) {
      // 优先使用思源自带剪贴板：移动端 WebView 不支持 navigator.clipboard
      try {
        if (platformUtils) {
          if (typeof platformUtils.copyPlainText === "function") {
            return Promise.resolve(platformUtils.copyPlainText(text));
          }
          if (typeof platformUtils.writeText === "function") {
            platformUtils.writeText(text);
            return Promise.resolve();
          }
        }
      } catch (e) {
        console.error("[text-encrypt]", e);
      }
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text).catch(() => this.copyViaExecCommand(text));
      }
      return this.copyViaExecCommand(text);
    }

    copyViaExecCommand(text) {
      return new Promise((resolve, reject) => {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        try {
          if (document.execCommand("copy")) {
            resolve();
          } else {
            reject(new Error("execCommand copy failed"));
          }
        } catch (e) {
          reject(e);
        } finally {
          document.body.removeChild(ta);
        }
      });
    }

    async encryptSelection(range, protyle) {
      const editor = this.resolveEditor(range, protyle);
      if (!editor) {
        showMessage("未找到可用的编辑器，请重新打开文档后再试", 4000, "error");
        return;
      }
      const blocks = this.getBlocksInRange(range, editor).filter((b) => SUPPORTED_TYPES.includes(b.type));
      if (blocks.length === 0) {
        showMessage("所选区域没有可加密的文本块", 3000, "error");
        return;
      }

      const dialog = new Dialog({
        title: "设置加密",
        content: `<div class="b3-dialog__content">
  <div class="b3-typography" style="margin-bottom:12px;">将为选中内容设置加密密码，共涉及 ${blocks.length} 个块。<br>请牢记密码，忘记后无法找回。</div>
  <input class="b3-text-field fn__block" id="encPwd1" type="password" inputmode="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="请输入加密密码">
  <input class="b3-text-field fn__block" id="encPwd2" type="password" inputmode="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="请再次输入密码" style="margin-top:8px;">
</div>
<div class="b3-dialog__action text-encrypt-actions">
  <button class="b3-button b3-button--cancel" id="encCancel">取消</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--text" id="encOk">加密</button>
</div>`,
        width: this.dialogWidth("92vw", "480px"),
        containerClassName: "text-encrypt-panel",
      });

      const input1 = dialog.element.querySelector("#encPwd1");
      const input2 = dialog.element.querySelector("#encPwd2");
      const okBtn = dialog.element.querySelector("#encOk");
      const cancelBtn = dialog.element.querySelector("#encCancel");
      this.assistKeyboard(dialog);
      this.bindDialogTapFocus(dialog, [input1, input2]);
      this.guardFocus(dialog, input1);

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
            const r = await this.encryptOneBlock(b, pwd, editor);
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
      this.focusInput(input1);
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
      const originalHTML = edit.innerHTML;
      if (full) {
        edit.textContent = ct;
      } else {
        const before = escapeHtml(text.slice(0, idx));
        const after = escapeHtml(text.slice(idx + textToEncrypt.length));
        edit.innerHTML = before + '<span data-type="code">' + escapeHtml(ct) + '</span>' + after;
      }
      if (!this.transactionUpdate(protyle, [{action: "update", id, data: element.outerHTML}])) {
        // 保存失败时回滚界面，避免出现"看起来加密了但其实没保存"的情况
        edit.innerHTML = originalHTML;
        showMessage("保存失败：未找到编辑器上下文，请重试", 4000, "error");
        return "no-protyle";
      }
      await setBlockAttr(id, ENCRYPTED_ATTR, ENCRYPTED_VALUE);
      return "ok";
    }

    async decryptSelection(range, protyle) {
      const editor = this.resolveEditor(range, protyle) || protyle;
      const blocks = this.getBlocksInRange(range, editor);
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
  <input class="b3-text-field fn__block" id="decPwd" type="password" inputmode="text" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false" placeholder="请输入加密密码">
</div>
<div class="b3-dialog__action text-encrypt-actions">
  <button class="b3-button b3-button--cancel" id="decCancel">取消</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--text" id="decOk">查看</button>
</div>`,
        width: this.dialogWidth("92vw", "480px"),
        containerClassName: "text-encrypt-panel",
      });

      const pwdInput = dialog.element.querySelector("#decPwd");
      const okBtn = dialog.element.querySelector("#decOk");
      const cancelBtn = dialog.element.querySelector("#decCancel");
      this.assistKeyboard(dialog);
      this.bindDialogTapFocus(dialog, [pwdInput]);
      this.guardFocus(dialog, pwdInput);

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
        this.showPlainDialog(restored, plainParts.join("\n\n"), editor);
      });
      dialog.bindInput(pwdInput, () => okBtn.click());
      this.focusInput(pwdInput);
    }

    showPlainDialog(restored, plain, protyle) {
      const resultDialog = new Dialog({
        title: "解密内容",
        content: `<div class="b3-dialog__content">
  <textarea class="b3-text-field fn__block" id="decPlain" readonly style="height:220px;">${escapeHtml(plain)}</textarea>
</div>
<div class="b3-dialog__action text-encrypt-actions">
  <button class="b3-button b3-button--cancel" id="decClose">关闭</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--outline" id="decCopy">复制</button>
  <div class="fn__space"></div>
  <button class="b3-button b3-button--text" id="decRestore">解密并恢复为明文（移除加密）</button>
</div>`,
        width: this.dialogWidth("92vw", "640px"),
        containerClassName: "text-encrypt-panel",
      });
      this.assistKeyboard(resultDialog);

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
              const found = this.findBlockElement(t.id, protyle);
              if (found) {
                const el = found.el;
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
            const attrRemoves = [];
            for (const t of restored) {
              attrRemoves.push(t.id);
              const found = this.findBlockElement(t.id, protyle);
              if (found) {
                const el = found.el;
                const root = found.root;
                let p = el.parentElement;
                while (p && p !== root) {
                  if (p.dataset && p.dataset.nodeId && p.hasAttribute(ENCRYPTED_ATTR)) {
                    const ownText = this.getBlockText(p) || "";
                    if (ownText.includes(PREFIX)) {
                      break;
                    }
                    attrRemoves.push(p.dataset.nodeId);
                  }
                  p = p.parentElement;
                }
              }
            }
            for (const id of Array.from(new Set(attrRemoves))) {
              await setBlockAttr(id, ENCRYPTED_ATTR, "");
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
