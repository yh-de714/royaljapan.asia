'use client'
import { useState, useEffect } from "react"
import axios from 'axios';
const baseurl = process.env.NEXT_PUBLIC_API_BASE_URL;
function Detail({id, user, coupon, count, setPrice}){
    const [price_sell, setPriceSell] = useState("");
    const [price_id, setPriceId] = useState("");
    const [description, setDescription] = useState("");
    const [title, setTitle] = useState("");
    const [image, setImage] = useState("");
    const [image1, setImage1] = useState("");
    const [image2, setImage2] = useState("");
    const [image3, setImage3] = useState("");
    const [percent, setPercent] = useState(0);
    const [subtitile, setSubTitle] = useState("");

    useEffect(()=>{
        getProductData()       
    },[])
    const getProductData = ()=>{      
        let config = {
            method: 'get',
            url: `${baseurl}/api/product/${id}`,
        };
        axios(config)
        .then(async (response) => {
            if(coupon)
            {
                getCoupon()
            }
            setPrice(response.data.price_sell * count)
            setPriceSell(response.data.price_sell);
            setPriceId(response.data.price_id);
            setDescription(response.data.description);
            setTitle(response.data.title);
            setImage(response.data.image);
            setImage1(response.data.image1);
            setImage2(response.data.image2);
            setImage3(response.data.image3);
            setSubTitle(response.data.package);
        })
        .catch((err)=>{

        })
    }

    const getCoupon = () =>{
        
        let data = JSON.stringify({
            'user':user,
            'coupon':coupon ? coupon : ""
        });
        let config = {
            method: 'post',
            url: `${baseurl}/api/coupon`,
            headers: { 
                'Content-Type': 'application/json'
            },
            data : data
        };
        axios(config)
        .then((response) => {
            setPercent(response.data.percent)
            
            if(response.data.percent!=0)
            {
                setPrice(price_sell * count)
            }
            else{
                setPrice(price_sell - price_sell * response.data.percent / 100)
            }
           
        })
        .catch((err)=>{

        })
    }

    return(
    
        <div className="wrap">
            <div className="detail-left pc">
                <div className="detail-main">
                    {image && <img src={image} alt=""/>}
                </div>
                <div className="detail-subimage">
                    <div className="detail-subimage-thumb">
                        {image1 && <img src={image1} alt=""/>}
                    </div>
                    <div className="detail-subimage-thumb">
                        {image2 && <img src={image2} alt=""/>}
                    </div>
                    <div className="detail-subimage-thumb">
                        {image3 && <img src={image3} alt=""/>}
                    </div>
                </div>
            </div>
            <div className="detail-right">
                <div className="detail-title">
                    {title}
                </div>
                <div className="detail-package">
                    {subtitile}
                </div>
                <p className="detail-text pc">
                    {description}
                </p>
                <div className="detail-count-sp">
                    <div className="detail-cost">
                        <div className="detail-count">
                            <p>数量</p>
                            <p>{count}</p>
                        </div>
                        <div className="detail-price">
                            <p>特別限定価格</p>
                            {percent !==0 && <p className="original">{parseInt(price_sell * count).toLocaleString('en-US').toString()}円 <span>(税込)</span></p>}
                            <p>{parseInt((price_sell - price_sell * percent / 100) * count).toLocaleString('en-US').toString()}円 <span>(税込)</span></p>
                        </div>
                    </div>
                    {/* <a href={`/order/${user}/${id}/${coupon}`} className="sp">今すぐ購入する</a> */}
                </div>
            </div>
            
        </div>
               
    )
}

export default Detail;