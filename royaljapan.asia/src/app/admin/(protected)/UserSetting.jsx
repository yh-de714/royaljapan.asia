"use client";

import { useState, useEffect } from "react";
// import { useParams } from 'react-router-dom';
import axios from "axios";
import { useParams } from "next/navigation";
const baseurl = process.env.REACT_APP_API_BASE_URL;

function UserSetting() {
  const { id } = useParams();
  const [username, setUserName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  useEffect(() => {
    getData();
  }, []);

  const getData = () => {
    var userData = JSON.parse(localStorage.getItem("userData")) || null;
    if (userData) {
      var token = userData.token;
      let config = {
        method: "get",
        url: `${baseurl}/api/get-user-data/${id}`,
        headers: {
          Authorization: "Bearer " + token,
        },
      };
      axios(config)
        .then((response) => {
          setUserName(response.data.name);
          setEmail(response.data.email);
        })
        .catch((err) => {
          if (err.response.status == 401) {
            localStorage.clear();
            window.location.assign("/admin/login");
          }
        });
    } else {
      window.location.assign("/admin/login");
    }
  };

  const handleSubmit = () => {
    if (password !== "") {
      var userData = JSON.parse(localStorage.getItem("userData")) || null;
      if (userData) {
        let token = userData.token;
        let data = JSON.stringify({
          password: password,
        });
        let config = {
          method: "post",
          url: `${baseurl}/api/update-password/${id}`,
          headers: {
            "Content-Type": "application/json",
            Authorization: "Bearer " + token,
          },
          data: data,
        };
        axios(config)
          .then((response) => {})
          .catch((err) => {
            if (err.response.status == 401) {
              localStorage.clear();
              window.location.assign("/admin/login");
            }
          });
      } else {
        window.location.assign("/admin/login");
      }
    }
  };

  return (
    <div className="container">
      <div className="card">
        <div className="product-card">
          <div className="product-card-title">登録者</div>

          <div className="product-card-items">
            <div className="product-card-item-name">名前</div>
            <div className="product-card-item-balance full-width">
              <div className="product-link">{username}</div>
            </div>
          </div>
          <div className="product-card-items">
            <div className="product-card-item-name">メールアドレス</div>
            <div className="product-card-item-balance full-width">
              <div className="product-link">{email}</div>
            </div>
          </div>
          <div className="product-card-items">
            <div className="product-card-item-name">販売リンク</div>
            <div className="product-card-item-balance full-width">
              <div className="product-link">{`https://royaljapan.asia/${id}`}</div>
            </div>
          </div>
          <div className="product-card-items">
            <div className="product-card-item-name">パスワード</div>
            <div className="product-card-item-balance full-width">
              <input
                className="product-link"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </div>
          <button onClick={handleSubmit} className="product-card-change">
            パスワードの更新
          </button>
        </div>
      </div>
    </div>
  );
}
export default UserSetting;
