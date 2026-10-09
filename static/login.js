"use strict";
const form = document.getElementById("form");
const err = document.getElementById("err");
const btn = document.getElementById("submit");

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  err.textContent = "";
  btn.disabled = true;
  btn.textContent = "확인 중…";
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        password: document.getElementById("pw").value,
        otp: document.getElementById("otp").value.trim(),
      }),
    });
    if (res.ok) {
      location.replace("/");
      return;
    }
    const data = await res.json().catch(() => ({}));
    err.textContent = typeof data.detail === "string" ? data.detail : "로그인에 실패했습니다.";
    document.getElementById("pw").select();
  } catch {
    err.textContent = "서버에 연결할 수 없습니다.";
  } finally {
    btn.disabled = false;
    btn.textContent = "로그인";
  }
});
