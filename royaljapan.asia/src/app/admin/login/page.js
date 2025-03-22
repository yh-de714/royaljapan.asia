"use client";
// import { useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useEffect, useState } from "react";
import axios from "axios";

const baseurl = process.env.NEXT_PUBLIC_API_BASE_URL;

function setUserData(userdata) {
  localStorage.setItem("userData", JSON.stringify(userdata));
}

function AdminLogin() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleSubmit = (event) => {
    event.preventDefault();
    let data = JSON.stringify({
      email: email,
      password: password,
    });
    let config = {
      method: "post",
      url: `${baseurl}/api/admin/login`,
      headers: {
        "Content-Type": "application/json",
      },
      data: data,
    };
    axios(config)
      .then(async (response) => {
        setUserData({
          token: response.data.token,
          refresh: response.data.refresh,
          status: response.data.userStatus,
        });
        window.location.assign("/admin/dashboard");
      })
      .catch((err) => {
        setError(true);
        setErrorMsg("ユーザーが見つかりません。");
      });
  };

  return (
    <section className="admin-mainvisual">
      <div id="login" className="register">
        <div className="register-title">
          <img src="/assets/images/logo.svg" alt="" />
          <h2>
            海外サプリメント個人輸入
            <br />
            <strong>管理者画面</strong>
          </h2>
        </div>
        <div className="form clearfix z-10">
          <form
            name="login_form"
            onSubmit={handleSubmit}
            id="login_form"
            action="#"
            method="post"
            className="register-form"
          >
            <div className="form-col">
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                type="text"
                name="user_name"
                id="username"
                className="form-control form-user-name"
                size="20"
                placeholder="ID"
              />
            </div>
            <div className="form-col">
              <input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="パスワード"
                type="password"
                name="pwd"
                id="password"
                className="form-control form-password"
              />
            </div>
            <input
              type="submit"
              id="login-button"
              className="btn btn-primary btn-lg btn-block"
              value="ログイン"
            />
            {error && <p className="register-message">{errorMsg}</p>}
          </form>
        </div>
      </div>
    </section>
  );
}
export default AdminLogin;
