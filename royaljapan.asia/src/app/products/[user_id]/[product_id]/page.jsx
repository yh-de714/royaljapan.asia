"use client";
// import { useParams } from 'react-router-dom';
import { useState, useEffect } from "react";
// import { useNavigate } from 'react-router-dom';
import Footer from "@/components/Footer";
import Header from "@/components/Header";
import Sitemap from "@/components/Sitemap";
// import Detail from '../components/Detail';
import axios from "axios";
import { useRouter } from "next/navigation";

const baseurl = process.env.NEXT_PUBLIC_API_BASE_URL;

function ProductDetail({ params }) {
  // const navigate = useNavigate()
  const router = useRouter();
  const { user_id, product_id } = params;
  const [coupon, setCoupon] = useState("");
  const [price_sell, setPrice] = useState("");
  const [price_id, setPriceId] = useState("");
  const [description, setDescription] = useState("");
  const [title, setTitle] = useState("");
  const [image, setImage] = useState("");
  const [image1, setImage1] = useState("");
  const [image2, setImage2] = useState("");
  const [image3, setImage3] = useState("");
  const [percent, setPercent] = useState(0);
  const [subtitile, setSubTitle] = useState("");
  const [count, setCount] = useState(10);
  useEffect(() => {
    getProductData();
  }, []);
  const getProductData = () => {
    let config = {
      method: "get",
      url: `${baseurl}/api/product/${product_id}`,
    };
    axios(config)
      .then(async (response) => {
        setPrice(response.data.price_sell);
        setPriceId(response.data.price_id);
        setDescription(response.data.description);
        setTitle(response.data.title);
        setImage(response.data.image);
        setImage1(response.data.image1);
        setImage2(response.data.image2);
        setImage3(response.data.image3);
        setSubTitle(response.data.package);
      })
      .catch((err) => {});
  };

  const handleSubmit = () => {
    if (count < 10) {
      setCount(10);
      router.push(`/order/${user_id}/${product_id}/${coupon}?count=10`);
    } else {
      router.push(`/order/${user_id}/${product_id}/${coupon}?count=${count}`);
    }
  };

  return (
    <>
      <Header />
      <div className="product">
        <section className="top pc">
          <div className="top-img">
            <Image
              width={100}
              height={100} src="/assets/images/top-img.png" alt="" />
            <Image
              width={100}
              height={100} src="/assets/images/top-img02.png" className="sp" alt="" />
          </div>
          <img src="/assets/images/logo.svg" alt="" />
          <p className="top-text1">
            ロイヤルジャパン
            <br />
            公式オンラインショッピング
          </p>
          <p className="top-text2">愛の証を超濃厚に、超濃密に</p>
          <p className="top-text3">ふたりだけの夜をもっと愉しむために</p>
        </section>
        <section className="detail">
          <div className="contain">
            <div className="wrap">
              <div className="detail-left">
                <div className="detail-main">
                  {image && <img src={image} alt="" />}
                </div>
                <div className="detail-subimage">
                  <div className="detail-subimage-thumb">
                    {image1 && <img src={image1} alt="" />}
                  </div>
                  <div className="detail-subimage-thumb">
                    {image2 && <img src={image2} alt="" />}
                  </div>
                  <div className="detail-subimage-thumb">
                    {image3 && <img src={image3} alt="" />}
                  </div>
                </div>
              </div>
              <div className="detail-right">
                <div className="detail-title">{title}</div>
                <div className="detail-package">{subtitile}</div>
                <p className="detail-text pc">{description}</p>
                <div className="detail-count-sp">
                  <div className="detail-cost">
                    <div className="detail-count">
                      <div style={{ color: "#8F121A", fontSize: "20px" }}>
                        数量{" "}
                        <span
                          style={{
                            color: "red",
                            fontSize: "16px",
                            marginLeft: "10px",
                          }}
                        >
                          ※最低10個〜
                        </span>
                      </div>
                      <div className="count-input">
                        <select
                          value={count}
                          onChange={(e) => {
                            setCount(e.target.value);
                          }}
                        >
                          <option value={10}> 10 </option>
                          <option value={15}> 15 </option>
                          <option value={20}> 20 </option>
                          <option value={25}> 25 </option>
                          <option value={30}> 30 </option>
                        </select>
                      </div>
                    </div>
                    <div className="detail-price">
                      <p>特別限定価格</p>
                      {percent !== 0 && (
                        <p className="original">
                          {parseInt(price_sell * count)
                            .toLocaleString("en-US")
                            .toString()}
                          円 <span>(税込)</span>
                        </p>
                      )}
                      <p>
                        {(
                          parseInt(price_sell - (price_sell * percent) / 100) *
                          count
                        )
                          .toLocaleString("en-US")
                          .toString()}
                        円 <span>(税込)</span>
                      </p>
                    </div>
                  </div>
                  <a onClick={handleSubmit} className="sp">
                    今すぐ購入する
                  </a>
                </div>
              </div>
            </div>
            <div className="form-input">
              <div className="label">紹介コード</div>
              <div className="input">
                <input
                  value={coupon}
                  onChange={(e) => setCoupon(e.target.value)}
                  type="text"
                  name="address"
                  placeholder="XXXXXXXXX"
                />
              </div>
            </div>
            <a onClick={handleSubmit} className="site-link pc">
              <p>購入する</p>
              <span></span>
            </a>
            <p className="detail-text sp">{description}</p>
          </div>
        </section>
      </div>
      <Footer />
      <Sitemap />
    </>
  );
}
export default ProductDetail;
