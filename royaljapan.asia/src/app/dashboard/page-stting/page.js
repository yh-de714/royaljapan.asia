
'use client'
// import { useNavigate} from "react-router-dom";
import {useState, useEffect} from 'react';
import axios from "axios";
const baseurl = process.env.REACT_APP_API_BASE_URL;

function PageSetting(props){
    const [imgurl, setImgurl] = useState("")
    const [displayData, setDisplayData] = useState({})
    useEffect(()=>{
        getPageData()
    },[])
    useEffect(()=>{
        displayData
    },[displayData])
    const getPageData = () =>{
        var userData =  JSON.parse(localStorage.getItem("userData")) || null;
        var token = userData?.token;
        let config = {
            method: 'get',
            url: `${baseurl}/api/get-page-data`,
            headers: {
                'Authorization': 'Bearer ' + token
            }
        };
        axios(config)
            .then((response) => {
                let tmp_data = {}
                response.data.settings.forEach(element => {
                    tmp_data = {...tmp_data, [element.key]:element.value}

                });
                setDisplayData(tmp_data)
            })
            .catch((err)=>{
                if(err.response.status==401){
                    localStorage.clear()
                    window.location.assign("/login")
                }

            })
    }
    const handleUpdate = (key) =>{
        var userData =  JSON.parse(localStorage.getItem("userData")) || null;
        var token = userData.token;
        if(key!=="delivery-description"){
            let updatedata = document.getElementById(`${key}`).value;
            let data = JSON.stringify({
                "key":key,
                "updatedata":updatedata
            });
            let config = {
                method: 'post',
                url: `${baseurl}/api/update-page`,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                data : data,
            };
            axios(config)
        }
        else{
            let updatedata = document.getElementById("delivery-main-description").value;
            let data = JSON.stringify({
                "key":"delivery-main-description",
                "updatedata":updatedata
            });
            let config = {
                method: 'post',
                url: `${baseurl}/api/update-page`,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + token
                },
                data : data,
            };
            axios(config)
                .then((res)=>{
                    updatedata = document.getElementById("delivery-sub-description").value;
                    data = JSON.stringify({
                        "key":"delivery-sub-description",
                        "updatedata":updatedata
                    });
                    config = {
                        method: 'post',
                        url: `${baseurl}/api/update-page`,
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': 'Bearer ' + token
                        },
                        data : data,
                    };
                    axios(config)
                })


        }

    }

    const handleClickImage = (key)=>{
        let fileInput = document.getElementById(`${key}`)
        fileInput.click()
    }

    const handleChangeImage = (key)=>{
        let fileInput = document.getElementById(`${key}`)
        var files = fileInput.files
        if (files) {
            let src = URL.createObjectURL(files[0])
            setImgurl(src)
        }
    }
    const handleUpload = (key)=>{
        let fileInput = document.getElementById(`${key}`)
        var files = fileInput.files
        if (files) {
            const fd = new FormData();
            fd.append("img", files[0])
            fd.append('key', key);
            var userData =  JSON.parse(localStorage.getItem("userData")) || null;
            var token = userData.token;
            let config = {
                method: 'post',
                url: `${baseurl}/api/update-deliver-img`,
                headers: {
                    'Content-Type': 'multipart/form-data',
                    'Authorization': 'Bearer ' + token
                },
                data: fd,
            };
            axios(config)
                .then((response) => {

                })
                .catch((error) => {
                    if (error.response) {
                        if (error.response.status === 403) {

                        }
                        if (error.response.status === 401) {
                            localStorage.removeItem("userData");
                            window.location.assign('/');
                        }
                    }
                })
        }
    }

    return(
        <div className="container">
            <div className="title">
                <p>配送・送料について</p>
            </div>
            <div className="card">
                <div className="product-card">
                    <div className="product-card-title">
                        <input defaultValue={displayData["delivery-title"]} id="delivery-title" type="text" placeholder="見出し１見出し１見出し１" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("delivery-title")}}>タイトルを変更</a>
                    </div>
                    <div className="product-card-title">
                        <input defaultValue={displayData["delivery-subtitle"]} id="delivery-subtitle" type="text" placeholder="Royal Mints 10 package" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("delivery-subtitle")}}>サブタイトルを変更</a>
                    </div>
                    <div className="detail">
                        <textarea defaultValue={displayData["delivery-main-description"]} className="main-txt" id="delivery-main-description"></textarea>
                        <div className="product-card-images">
                            <div className="product-card-images-item">
                                <div className="product-card-images-item-thumb" onClick={()=>handleClickImage("delivery-image")}>
                                    <img src={displayData["delivery-image"]}  alt=""/>
                                </div>
                                <input  id="delivery-image" type="file"  accept="image/*" hidden onChange={()=>handleChangeImage("delivery-image")}/>
                                <div className="product-card-images-item-title">
                                    メイン画像
                                </div>
                                <a onClick={()=>handleUpload("delivery-image")} className="product-card-change">写真をアップロード</a>
                            </div>
                            <textarea defaultValue={displayData["delivery-sub-description"]} id="delivery-sub-description"></textarea>
                        </div>
                    </div>
                    <div className="product-card-details" style={{marginTop:"10px"}}>
                        <a className="product-card-change" onClick={()=>{handleUpdate("delivery-description")}}>更新</a>
                    </div>
                </div>
            </div>
            <div className="title sub">
                <p>特定商取引法に基づく表記</p>
            </div>
            <div className="card">
                <div className="product-card">
                    <div className="product-card-title">
                        <input defaultValue={displayData["specified-title"]} id="specified-title" type="text" placeholder="見出し１見出し１見出し１" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("specified-title")}}>タイトルを変更</a>
                    </div>
                    <div className="product-card-title">
                        <input defaultValue={displayData["specified-subtitle"]} id="specified-subtitle" type="text" placeholder="Royal Mints 10 package" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("specified-subtitle")}}>サブタイトルを変更</a>
                    </div>
                    <div className="product-card-details" style={{marginTop:"10px"}}>
                        <textarea defaultValue={displayData["specified-description"]} className="main-txt" id="specified-description"></textarea>
                        <a className="product-card-change" onClick={()=>{handleUpdate("specified-description")}}>更新</a>
                    </div>
                </div>
            </div>

            <div className="title sub">
                <p>個人輸入・薬事法・関税について</p>
            </div>
            <div className="card">
                <div className="product-card">
                    <div className="product-card-title">
                        <input defaultValue={displayData["protected-title"]} id="protected-title" type="text" placeholder="見出し１見出し１見出し１" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("protected-title")}}>タイトルを変更</a>
                    </div>
                    <div className="product-card-title">
                        <input defaultValue={displayData["protected-subtitle"]} id="protected-subtitle" type="text" placeholder="Royal Mints 10 package" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("protected-subtitle")}}>サブタイトルを変更</a>
                    </div>
                    <div className="product-card-details" style={{marginTop:"10px"}}>
                        <textarea defaultValue={displayData["protected-description"]} id="protected-description" className="main-txt"></textarea>
                        <a className="product-card-change" onClick={()=>{handleUpdate("protected-description")}}>更新</a>
                    </div>
                </div>
            </div>
            <div className="title sub">
                <p>利用規約</p>
            </div>
            <div className="card">
                <div className="product-card">
                    <div className="product-card-title">
                        <input defaultValue={displayData["privacy-title"]} id="privacy-title" type="text" placeholder="見出し１見出し１見出し１" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("privacy-title")}}>タイトルを変更</a>
                    </div>
                    <div className="product-card-title">
                        <input defaultValue={displayData["privacy-subtitle"]} id="privacy-subtitle" type="text" placeholder="Royal Mints 10 package" />
                        <a className="product-card-change" onClick={()=>{handleUpdate("privacy-subtitle")}}>サブタイトルを変更</a>
                    </div>
                    <div className="product-card-details" style={{marginTop:"10px"}}>
                        <textarea defaultValue={displayData["privacy-description"]} id="privacy-description" className="main-txt"></textarea>
                        <a className="product-card-change" onClick={()=>{handleUpdate("privacy-description")}}>更新</a>
                    </div>
                </div>
            </div>
            <a href="#home" className="back-top">▲ 上に戻る</a>
        </div>
    )
}

export default PageSetting;