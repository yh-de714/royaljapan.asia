"use client";
// import { useNavigate} from "react-router-dom";
import { useState } from "react";
import axios from "axios";
import { useRouter } from "next/navigation";

const baseurl = process.env.NEXT_PUBLIC_API_BASE_URL;

function Register() {
  // const navigate = useNavigate();
  // const router = useRouter()
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handleSubmit = (event) => {
    event.preventDefault();
    if (password == "" || email == "" || name == "") {
      setError(true);
      setErrorMsg("ユーザー名とメールアドレスは必須です。");
    } else {
      let data = JSON.stringify({
        name: name,
        email: email,
        password: password,
      });
      let config = {
        method: "post",
        url: `${baseurl}/api/register`,
        headers: {
          "Content-Type": "application/json",
        },
        data: data,
      };
      axios(config)
        .then((response) => {
          window.location.assign("/login?ref=register");
        })
        .catch((error) => {
          if (error.response) {
            if (error.response.data) {
              var errordata = error.response.data;
              if (errordata.email) {
                setError(true);
                setErrorMsg(
                  "この電子メール アドレスを持つユーザーは既に存在します。",
                );
              }
            }
          }
        });
    }
  };

  return (
    <section className="mainvisual">
      <div id="register" className="register">
        <div className="register-title">
          <img src="/assets/images/logo.svg" alt="" />
          <h2>
            海外サプリメント個人輸入
            <br />
            <strong>紹介者専用サイト</strong>
          </h2>
          <div className="page-title">新規アカウント登録</div>
        </div>
        <div className="form clearfix z-10">
          <form
            className="register-form"
            onSubmit={handleSubmit}
            name="register-form"
            id="registration_form"
          >
            <div className="first form-col">
              <label for="new_user_name">あなたのお名前</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                type="text"
                name="new_user_name"
                id="new-username"
                className="form-control input-lg"
                placeholder=""
                required
              />
            </div>
            <div className="form-col">
              <label for="">メール</label>
              <input
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                type="email"
                name="new_user_email"
                id="new-useremail"
                className="form-control input-lg"
                placeholder=""
                required
              />{" "}
            </div>
            <div className="first form-col">
              <label for="new_user_password">パスワード（小文字英数字）</label>
              <input
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                type="password"
                id="new-userpassword"
                name="new_user_password"
                className="form-control input-lg"
                placeholder=""
                required
              />
            </div>
            <input
              type="submit"
              id="register-button"
              className="btn btn-primary btn-lg btn-block"
              value="登録"
            />
            {error && <p className="register-message">{errorMsg}</p>}
            <a href="/login" id="login">
              ログイン画面に戻る
            </a>
          </form>
        </div>
      </div>
    </section>
  );
}
export default Register;
