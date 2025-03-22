"use client";
// import { useNavigate} from "react-router-dom";
import { useState, useEffect } from "react";
import axios from "axios";
const baseurl = process.env.REACT_APP_API_BASE_URL;

function ProductSetting(props) {
  const [products, setProducts] = useState(props.products);
  useEffect(() => {
    setProducts(props.products);
  }, [props]);

  const handleUpdate = (key, price_id) => {
    var userData = JSON.parse(localStorage.getItem("userData")) || null;
    var token = userData.token;
    let updatedata = document.getElementById(`${key}-${price_id}`).value;
    let data = JSON.stringify({
      price_id: price_id,
      updatedata: updatedata,
    });
    let config = {
      method: "post",
      url: `${baseurl}/api/update-${key}`,
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

  const handleClickImage = (key, id) => {
    let fileInput = document.getElementById(`${key}-${id}`);
    fileInput.click();
  };

  const handleChangeImage = (key, id) => {
    let fileInput = document.getElementById(`${key}-${id}`);
    var files = fileInput.files;
    if (files) {
      let src = URL.createObjectURL(files[0]);
      let tem = products?.map((item) => {
        if (item.id == id) {
          return { ...item, [key]: src };
        } else {
          return item;
        }
      });
      setProducts(tem);
    }
  };
  const handleUpload = (key, id) => {
    let fileInput = document.getElementById(`${key}-${id}`);
    var files = fileInput.files;
    if (files) {
      const fd = new FormData();
      fd.append("img", files[0]);
      fd.append("key", key);
      fd.append("price_id", id);
      var userData = JSON.parse(localStorage.getItem("userData")) || null;
      var token = userData.token;
      let config = {
        method: "post",
        url: `${baseurl}/api/update-image`,
        headers: {
          "Content-Type": "multipart/form-data",
          Authorization: "Bearer " + token,
        },
        data: fd,
      };
      axios(config)
        .then((response) => {})
        .catch((error) => {
          if (error.response) {
            if (error.response.status === 403) {
            }
            if (error.response.status === 401) {
              localStorage.removeItem("userData");
              window.location.assign("/");
            }
          }
        });
    }
  };

  return (
    <div className="container">
      <div className="title">
        <p>サイトに並んでいる商品の編集が可能です。</p>
      </div>
      <div className="card">
        {products?.map((item, index) => (
          <div className="product-card" key={index}>
            <div className="product-card-title">
              <input
                type="text"
                placeholder="商品A：ロイヤルミント（10缶入り）"
                id={`title-${item.id}`}
                defaultValue={item.title}
              />
              <a
                className="product-card-change"
                onClick={() => {
                  handleUpdate("title", item.id);
                }}
              >
                タイトルを変更
              </a>
            </div>
            <div className="product-card-title">
              <input
                type="text"
                placeholder="Royal Mints 10 package"
                id={`subtitle-${item.id}`}
                defaultValue={item.package}
              />
              <a
                className="product-card-change"
                onClick={() => {
                  handleUpdate("subtitle", item.id);
                }}
              >
                サブタイトルを変更
              </a>
            </div>
            <div className="product-card-images">
              <div className="product-card-images-item">
                <div
                  className="product-card-images-item-thumb"
                  onClick={() => handleClickImage("image", item.id)}
                >
                  <img src={item.image} alt="" />
                </div>
                <input
                  type="file"
                  id={`image-${item.id}`}
                  accept="image/*"
                  hidden
                  onChange={() => handleChangeImage("image", item.id)}
                />
                <div className="product-card-images-item-title">メイン画像</div>
                <a
                  onClick={() => handleUpload("image", item.id)}
                  className="product-card-change"
                >
                  写真をアップロード
                </a>
              </div>
              <div className="product-card-images-item">
                <div
                  className="product-card-images-item-thumb"
                  onClick={() => handleClickImage("image1", item.id)}
                >
                  <img src={item.image1} alt="" />
                </div>
                <input
                  type="file"
                  id={`image1-${item.id}`}
                  accept="image/*"
                  hidden
                  onChange={() => handleChangeImage("image1", item.id)}
                />
                <div className="product-card-images-item-title">サブ画像2</div>
                <a
                  onClick={() => handleUpload("image1", item.id)}
                  className="product-card-change"
                >
                  写真をアップロード
                </a>
              </div>
              <div className="product-card-images-item">
                <div
                  className="product-card-images-item-thumb"
                  onClick={() => handleClickImage("image2", item.id)}
                >
                  <img src={item.image2} alt="" />
                </div>
                <input
                  type="file"
                  id={`image2-${item.id}`}
                  accept="image/*"
                  hidden
                  onChange={() => handleChangeImage("image2", item.id)}
                />
                <div className="product-card-images-item-title">サブ画像3</div>
                <a
                  onClick={() => handleUpload("image2", item.id)}
                  className="product-card-change"
                >
                  写真をアップロード
                </a>
              </div>
              <div
                className="product-card-images-item"
                onClick={() => handleClickImage("image3", item.id)}
              >
                <div className="product-card-images-item-thumb">
                  <img src={item.image3} alt="" />
                </div>
                <input
                  type="file"
                  id={`image3-${item.id}`}
                  accept="image/*"
                  hidden
                  onChange={() => handleChangeImage("image3", item.id)}
                />
                <div className="product-card-images-item-title">サブ画像4</div>
                <a
                  onClick={() => handleUpload("image3", item.id)}
                  className="product-card-change"
                >
                  写真をアップロード
                </a>
              </div>
            </div>
            <div className="product-card-details">
              <textarea
                name=""
                id={`description-${item.id}`}
                defaultValue={item.description}
              ></textarea>
              <a
                className="product-card-change"
                onClick={() => {
                  handleUpdate("description", item.id);
                }}
              >
                商品説明を変更
              </a>
            </div>
          </div>
        ))}
      </div>
      <a href="#home" className="back-top">
        ▲ 上に戻る
      </a>
    </div>
  );
}

export default ProductSetting;
