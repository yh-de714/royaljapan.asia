"use client";
// import { useNavigate, useSearchParams} from "react-router-dom";
import { useEffect, useState } from "react";
import axios from "axios";
import { useSearchParams } from "next/navigation";
import { useRouter } from "next/router";

const baseurl = process.env.NEXT_PUBLIC_API_BASE_URL;

function setUserData(userdata) {
  localStorage.setItem("userData", JSON.stringify(userdata));
}

function Login({}) {
  // const useSearchParams()
  const searchParams = useSearchParams();
  const ref = searchParams?.get("ref");
  // const {ref} = params;

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  useEffect(() => {
    if (ref) {
      setError(true);
      setErrorMsg("登録が完了しました。ログインして下さい。");
    }
  }, [ref]);
  const handleSubmit = (event) => {
    event.preventDefault();
    let data = JSON.stringify({
      email: email,
      password: password,
    });
    let config = {
      method: "post",
      url: `${baseurl}/api/login`,
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
        window.location.assign("/dashboard");
      })
      .catch((err) => {
        if (err.response.data.non_field_errors[0] == "not found") {
          setError(true);
          setErrorMsg("ユーザーが見つかりません。");
        } else {
          setError(true);
          setErrorMsg("パスワードが違います。");
        }
      });
  };

  return (
    <section className="mainvisual">
      <div id="login" className="register">
        <div className="register-title">
          <img src="/assets/images/logo.svg" alt="" />
          <h2>
            海外サプリメント個人輸入
            <br />
            <strong>紹介者専用サイト</strong>
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
            <div className="form-col">
              <input
                type="checkbox"
                id="agree"
                name="agree"
                className="form-control"
                placeholder=""
              />
              <label htmlFor="agree">
                利用規約とプライバシーポリシーに同意します。
              </label>
            </div>
            <input
              type="submit"
              id="login-button"
              className="btn btn-primary btn-lg btn-block"
              value="ログイン"
            />
            {error && <p className="register-message">{errorMsg}</p>}
            <a
              href="/register"
              id="register"
              className="btn btn-primary btn-lg btn-block"
            >
              新規登録
            </a>
          </form>
        </div>
      </div>
    </section>
  );
}
export default Login;
