/* Apply a saved theme in <head>, before the first paint. */
(() => {
  "use strict";
  const storageKey = "orionis-theme";
  const validThemes = ["system", "light", "dark"];
  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = "system";
  try {
    const saved = localStorage.getItem(storageKey);
    if (validThemes.includes(saved)) preference = saved;
  } catch (_) {
    /* System appearance works without storage. */
  }
  function applyTheme() {
    document.documentElement.dataset.theme =
      preference === "system"
        ? systemTheme.matches
          ? "dark"
          : "light"
        : preference;
  }
  applyTheme();
  systemTheme.addEventListener("change", () => {
    if (preference === "system") applyTheme();
  });
  document.addEventListener("DOMContentLoaded", () => {
    const picker = document.querySelector("[data-theme-picker]");
    if (picker) {
      picker.value = preference;
      picker.closest(".theme-control").hidden = false;
      picker.addEventListener("change", () => {
        preference = validThemes.includes(picker.value)
          ? picker.value
          : "system";
        applyTheme();
        try {
          localStorage.setItem(storageKey, preference);
        } catch (_) {
          /* Optional persistence. */
        }
      });
    }
    const status = document.querySelector("[data-copy-status]");
    document.querySelectorAll(".code-block").forEach((block) => {
      const code = block.querySelector("pre code");
      const toolbar = block.querySelector(".code-toolbar");
      if (!code || !toolbar) return;
      const button = document.createElement("button");
      button.type = "button";
      button.className = "copy-button";
      button.textContent = "Copy";
      button.setAttribute(
        "aria-label",
        `Copy ${toolbar.textContent.trim()} code`,
      );
      let resetTimer;
      button.addEventListener("click", async () => {
        clearTimeout(resetTimer);
        try {
          await navigator.clipboard.writeText(code.textContent);
          button.textContent = "Copied!";
          if (status) status.textContent = "Code copied to clipboard.";
        } catch (_) {
          const range = document.createRange();
          range.selectNodeContents(code);
          const selection = window.getSelection();
          selection.removeAllRanges();
          selection.addRange(range);
          button.textContent = "Code selected";
          if (status)
            status.textContent =
              "Automatic copy is unavailable. Code selected; use your keyboard to copy.";
        }
        resetTimer = setTimeout(() => {
          button.textContent = "Copy";
          if (status) status.textContent = "";
        }, 2500);
      });
      toolbar.appendChild(button);
    });
  });
})();
