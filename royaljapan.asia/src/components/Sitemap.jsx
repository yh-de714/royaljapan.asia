
function SiteMap(){

    return (
        <div className="sitemap">
			<div className="contain">
				<div className="footer-logo sp">
					<img src="/assets/images/header_logo_sp.svg" alt=""/>
				</div>
				<div className="sitemap-left">
					<div className="sitemap-part">
						<div className="sitemap-item">
							特定商取引法に基づく表記
						</div>
						<div className="sitemap-item">
							個人情報の取扱について
						</div>
						<div className="sitemap-item">
							ご利用規約
						</div>
						<div className="sitemap-item">
							サイトマップ
						</div>
					</div>
					<div className="sitemap-copyright pc">
						{/* ※「タカミスキンピール」は株式会社タカミの登録商標です。 ※「タカミ式」はタカミクリニックの登録商標です。<br/> */}
						Copyright © ROYAL JAPAN All rights reserved. <br/>
						MALYSIA
					</div>
					<div className="sitemap-copyright sp">
						Copyright © ROYAL JAPAN All rights reserved. <br/>
						MALYSIA
					</div>
				</div>
				<div className="sitemap-right pc">
					<img src="/assets/images/logo.svg" alt=""/>
					<div className="sitemap-title">
						ロイヤルジャパン公式通販サイト
					</div>
				</div>
			</div>
		</div>
    )
}
export default SiteMap;