"use client";
import { useState, useEffect } from "react";
import axios from "axios";
import { useRouter } from "next/navigation";
// import { useNavigate } from "react-router-dom";
const baseurl = process.env.REACT_APP_API_BASE_URL;

function UserList() {
  // const navigate = useNavigate()
  const router = useRouter();
  const [users, setUsers] = useState([]);

  useEffect(() => {
    getData();
  }, []);

  const getData = () => {
    var userData = JSON.parse(localStorage.getItem("userData")) || null;
    if (userData) {
      var token = userData.token;
      let config = {
        method: "get",
        url: `${baseurl}/api/get-users`,
        headers: {
          Authorization: "Bearer " + token,
        },
      };
      axios(config)
        .then((response) => {
          console.log(response.data);
          setUsers(response.data.users);
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

  return (
    <div className="container">
      <div className="card">
        <div className="product-card">
          <div className="product-card-title">登録者一覧</div>
          <div className="product-card-items">
            <table>
              <thead style={{ backgroundColor: "#F1F3F9" }}>
                <tr>
                  <td
                    style={{
                      width: "60px",
                      border: "solid 1px",
                      textAlign: "center",
                      margin: 0,
                    }}
                  >
                    No
                  </td>
                  <td
                    style={{
                      width: "80px",
                      border: "solid 1px",
                      textAlign: "center",
                      margin: 0,
                    }}
                  >
                    お名前
                  </td>
                  <td
                    style={{
                      width: "120px",
                      border: "solid 1px",
                      textAlign: "center",
                      margin: 0,
                    }}
                  >
                    ログインID
                  </td>
                  {/* <td  style={{width:"120px", border:"solid 1px", textAlign:"center",  margin:0}}>登録日時</td> */}
                  <td
                    style={{
                      width: "600px",
                      border: "solid 1px",
                      textAlign: "center",
                      margin: 0,
                    }}
                  >
                    URL
                  </td>
                  <td
                    style={{
                      width: "120px",
                      border: "solid 1px",
                      textAlign: "center",
                      margin: 0,
                    }}
                  ></td>
                </tr>
              </thead>
              <tbody>
                {users.map((item, index) => (
                  <tr key={index}>
                    <td
                      style={{
                        width: "80px",
                        border: "solid 1px",
                        textAlign: "center",
                        margin: 0,
                      }}
                    >
                      {index + 1}
                    </td>
                    <td
                      style={{
                        width: "80px",
                        border: "solid 1px",
                        textAlign: "center",
                        margin: 0,
                      }}
                    >
                      {item.username}
                    </td>
                    <td
                      style={{
                        width: "120px",
                        border: "solid 1px",
                        textAlign: "center",
                        margin: 0,
                      }}
                    >
                      {item.email}
                    </td>
                    {/* <td  style={{width:"120px", border:"solid 1px", textAlign:"center",  margin:0}}>登録日時</td> */}
                    <td
                      style={{
                        width: "600px",
                        border: "solid 1px",
                        textAlign: "center",
                        margin: 0,
                      }}
                    >{`https://royaljapan.asia/${item.id}`}</td>
                    <td
                      style={{
                        width: "120px",
                        border: "solid 1px",
                        textAlign: "center",
                        margin: 0,
                      }}
                    >
                      <button
                        onClick={() => router.push(`/admin/user/${item.id}`)}
                        style={{ padding: "5px 15px" }}
                      >
                        {" "}
                        設定{" "}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
export default UserList;
