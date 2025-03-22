"use client";
// import {BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';

import UserList from "./UserList";
import UserSetting from "./UserSetting";

function Dashboard() {
  const handleLogout = () => {
    localStorage.clear();
    window.location.assign("/admin/login");
  };

  return (
    <div id="home" className="admin-home">
      <aside>
        <div className="home-logo">
          <div className="register-title">
            <img src="/assets/images/logo.svg" alt="" />
            <h2>
              海外サプリメント個人輸入
              <br />
              <strong>管理者画面</strong>
            </h2>
          </div>
        </div>

        <a href="/admin/(protected)/dashboard" className="home-btn">
          <img src="/assets/images/home.svg" alt="" />
          <p>ホーム</p>
        </a>
      </aside>
      <main>
        <div className="head">
          <a href="#" className="breadcrumb">
            <img src="/assets/images/home-white.svg" alt="" />
            <p>ホーム</p>
          </a>
          <div onClick={handleLogout} href="#" id="logout" className="logout">
            ログアウト ▼
          </div>
        </div>
        {/*<Routes>*/}
        {/*    <Route path="/dashboard" element={<UserList />} />*/}
        {/*    <Route path="/user/:id" element={<UserSetting />} />*/}
        {/*</Routes>*/}
      </main>
    </div>
  );
}
export default Dashboard;
