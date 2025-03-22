// import { useNavigate } from "react-router-dom";
import { useEffect, useState } from "react";
import {useRouter} from "next/navigation";

function Header(){
    const [show, setShow] = useState(false)
    // const navigate = useNavigate()
    const router = useRouter()

    const goHome = ()=>{
        
        let id = localStorage.getItem("userID");
        router.push(`/${id}`)
    }
     return (
      
        <>
            <header>
                <div className="logo">
                    <a href="/"><img src="/assets/images/header-logo.png" className="pc" alt=""/><img src="/assets/images/header_logo_sp.svg" className="sp" alt=""/></a>
                </div>
                <div className="menu pc">
                    {/* <a href="/" className="menu-item">HOME</a>
                    <a href="/product" className="menu-item">商品一覧</a>
                    <a href="/" className="menu-item">当サイトについて</a>
                    <a href="/" className="menu-item">お客様の声</a>
                    <a href="/" className="menu-item">Q&A</a> */}
                </div>
                <div className="cart pc">
                    <a href="/" className="cart-item">
                        <img src="/assets/images/Intersection.svg" alt=""/>
                    </a>
                    <div className="badge">0</div>
                </div>
                <div onClick={()=>setShow(true)} className="navMenu sp" id="navMenu">
                    <span>MENU</span>
                    <div className="menuItem">
                        <div className="bar"></div>
                        <div className="bar"></div>
                    </div>
                </div>
            </header>

            <div id="sideMenu" className={`sideMenu ${show?"show":""}`}>
                <div className="sidelogo">
                    <img src="/assets//images/header_logo_sp.svg" alt=""/>
                </div>
                <div onClick={()=>setShow(false)} className="close" id="closeMenu">
                    <div className="close-item">
                    </div>
                    <span>とじる</span>
                </div>
                <div className="sidemenu-part">
                    <a onClick={()=>goHome()} className="sidemenu-item">
                        <img src="/assets/images/icon-heart.svg" alt=""/>
                        <p>ホーム</p>
                    </a>
                    {/* <a href="" className="sidemenu-item">
                        <img src="/assets/images/icon-about.svg" alt=""/>
                        <p>私たちについて</p>
                    </a>
                    <a href="" className="sidemenu-item">
                        <img src="/assets/images/Icon-home.svg" alt=""/>
                        <p>お支払い方法</p>
                    </a> */}
                    <a href="/delivery" className="sidemenu-item">
                        <img src="/assets/images/icon-face.svg" alt=""/>
                        <p>配送・送料について</p>
                    </a>
                    <a href="/specified" className="sidemenu-item">
                        <img src="/assets/images/icon-comment.svg" alt=""/>
                        <p>特定商取引法に基づく表記</p>
                    </a>
                    <a href="/personal" className="sidemenu-item">
                        <img src="/assets/images/icon-bell.svg" alt=""/>
                        <p>個人輸入・薬事法・関税について</p>
                    </a>
                    <a href="/privacy" className="sidemenu-item">
                        <img src="/assets/images/icon-person.svg" alt=""/>
                        <p>利用規約</p>
                    </a>
                </div>
                <div className="sidemenu-footer">
                    ETUMAX日本正規代理店｜<br/>
                    ETUMAX Japan <br/><br/>
                    <span>メーカーETUMAX社の日本正規代理店「ETUMAX Japan」が運営をしております。<br/>
                        最安・安心・安全に、全品送料無料でメーカー直送の正規品をお買い求めいただけます。</span>
                </div>
            </div>
        </>
    )
}

export default Header;