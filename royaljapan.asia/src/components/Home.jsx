import { useState, useEffect } from "react";
import axios from "axios";
import { useRouter } from "next/navigation";
const baseurl = process.env.NEXT_PUBLIC_API_BASE_URL;

function Home({ userid, username, products, coupons, sellCount, profit }) {
  // const navigate = useNavigate()
  const router = useRouter();
  const handleUpdate = (price_id) => {
    var userData = JSON.parse(localStorage.getItem("userData")) || null;
    var token = userData.token;
    let updatedata = document.getElementById(`price-${price_id}`).value;

    let data = JSON.stringify({
      price_id: price_id,
      updatedata: updatedata,
    });
    let config = {
      method: "post",
      url: `${baseurl}/api/update-price`,
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
      data: data,
    };
    axios(config)
      .then(async (response) => {})
      .catch((err) => {});
  };

  const handleResetCoupon = () => {
    var userData = JSON.parse(localStorage.getItem("userData")) || null;
    var token = userData.token;
    let config = {
      method: "post",
      url: `${baseurl}/api/update-coupon`,
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + token,
      },
    };
    axios(config)
      .then(async (response) => {
        window.location.reload();
      })
      .catch((err) => {});
  };
  return (
    <div className="container">
      <div className="title">
        <p>ようこそ　こちらは紹介者専用サイトです。</p>
      </div>
      <div className="card">
        <div className="product-card">
          <div className="product-card-items">
            <div className="product-card-item-name">あなたのお名前</div>
            <div className="product-card-item-balance full-width">
              <div className="product-link">{username}</div>
            </div>
          </div>
          <div className="product-card-items">
            <div className="product-card-item-name">あなたの販売リンク</div>
            <div className="product-card-item-balance full-width">
              <div className="product-link">{`https://royaljapan.asia/${userid}`}</div>
            </div>
          </div>
          <div className="product-card-rank">
            <div className="product-card-blank"></div>
            <p>
              上記のリンク以外で購入したユーザーは販売実績に含まれません。
              <br />
              SNS等で宣伝する時は必ず上記のリンクをご使用下さい。
            </p>
          </div>
          <button
            onClick={() => router.push(`/${userid}`)}
            className="product-card-change"
          >
            サイトを見る
          </button>
        </div>

        {products.map((item, index) => (
          <div key={index} className="product-card">
            <div className="product-card-title">{item.title}</div>
            <div className="product-card-items">
              <div className="product-card-item-name">商品定価</div>
              <div className="product-card-item-balance">
                <input
                  id={`price-${item.id}`}
                  type="text"
                  defaultValue={parseInt(item.price_sell)
                    .toLocaleString("en-US")
                    .toString()}
                />
              </div>
              <div className="product-card-item-unit">円</div>
              <div className="product-card-change">変更可</div>
            </div>
            <p style={{ color: "red", marginTop: "-25px", textAlign: "right" }}>
              数値を変更するときは、カンマを入れずに
              <br />
              入力して「更新」ボタンを押してください。
            </p>
            <div className="product-card-items">
              <div className="product-card-item-name">仕入れ価格</div>
              <div className="product-card-item-balance">
                <input
                  type="text"
                  defaultValue={parseInt(item.price_origin)
                    .toLocaleString("en-US")
                    .toString()}
                />
              </div>
              <div className="product-card-item-unit">円</div>
              <div className="product-card-change impossible">変更不可</div>
            </div>

            <div className="product-card-rank">
              <div className="product-card-blank"></div>
              <p>
                仕入れ価格はあなたの販売実績に応じて変動します
                <br />
                現在のあなたのランク：<strong>ブロンズ</strong>
              </p>
            </div>
            <div className="product-card-items">
              <div className="product-card-item-name">販売時の利益</div>
              <div className="product-card-item-balance">
                <input
                  type="text"
                  defaultValue={parseInt(item.price_sell - item.price_origin)
                    .toLocaleString("en-US")
                    .toString()}
                />
              </div>
              <div className="product-card-item-unit">円</div>
              <div className="product-card-change impossible">変更不可</div>
            </div>
            <button
              className="product-card-change"
              onClick={() => {
                handleUpdate(item.id);
              }}
            >
              更新
            </button>
          </div>
        ))}
        <div className="product-card">
          <div className="product-card-title">紹介コード</div>
          {coupons.map((item, index) => (
            <div key={index} className="product-card-items">
              <div className="product-card-item-name">{item.percent}%</div>
              <div className="product-card-item-balance">
                <input type="text" defaultValue={item.code} />
              </div>
            </div>
          ))}

          <button onClick={handleResetCoupon} className="product-card-change">
            リセット
          </button>
        </div>
        <div className="product-card">
          <div className="product-card-title">実績</div>

          <div className="product-card-items">
            <div className="product-card-item-name">販売数</div>
            <div className="product-card-item-balance">
              <input type="text" defaultValue={sellCount} />
            </div>
            <div className="product-card-item-unit">円</div>
          </div>
          <div className="product-card-items">
            <div className="product-card-item-name">報酬額</div>
            <div className="product-card-item-balance">
              <input type="text" defaultValue={profit} />
            </div>
            <div className="product-card-item-unit">円</div>
          </div>
          <div className="product-card-rank">
            <div className="product-card-blank"></div>
            <p>報酬は翌月末に指定の銀行口座に振り込まれます。</p>
          </div>
          <button href="" className="product-card-change">
            振込先情報の確認/設定
          </button>
          <div className="blur">システムメンテナンス中</div>
        </div>
      </div>
      <a href="/dashboard#" className="back-top">
        ▲ 上に戻る
      </a>
    </div>
  );
}

export default Home;
