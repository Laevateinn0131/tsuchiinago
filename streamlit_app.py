import streamlit as st
import google.generativeai as genai
import requests
import re
import urllib.parse
from PIL import Image
import io
import base64
from urllib.parse import urlparse
import whois
import ssl
import socket
from datetime import datetime

# ページ設定
st.set_page_config(
    page_title="セキュリティチェッカー",
    page_icon="🔒",
    layout="wide"
)

# サイドバーでAPI キー設定
st.sidebar.title("⚙️ 設定")
api_key = st.sidebar.text_input("Google AI API Key", type="password")

def check_url_safety(url):
    """URLの安全性をチェック"""
    safety_score = 100
    warnings = []
    
    try:
        # URLの構造チェック
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            warnings.append("⚠️ 無効なURL形式")
            safety_score -= 30
        
        # HTTPSチェック
        if parsed.scheme != 'https':
            warnings.append("⚠️ HTTPSではありません")
            safety_score -= 20
        
        # 危険なドメインパターンチェック
        suspicious_patterns = [
            r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',  # IPアドレス
            r'[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.',  # ハイフンの多用
            r'[0-9]{8,}',  # 長い数字列
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, parsed.netloc):
                warnings.append(f"⚠️ 疑わしいドメイン形式: {parsed.netloc}")
                safety_score -= 25
                break
        
        # SSL証明書チェック
        try:
            context = ssl.create_default_context()
            with socket.create_connection((parsed.netloc, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                    cert = ssock.getpeercert()
                    # 証明書の有効期限チェック
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        warnings.append("⚠️ SSL証明書が期限切れ")
                        safety_score -= 40
        except:
            warnings.append("⚠️ SSL証明書の確認ができません")
            safety_score -= 15
        
    except Exception as e:
        warnings.append(f"❌ URLチェックエラー: {str(e)}")
        safety_score = 0
    
    return max(0, safety_score), warnings

def analyze_with_gemini(model, prompt, image=None):
    """Geminiで分析"""
    try:
        if image:
            response = model.generate_content([prompt, image])
        else:
            response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"エラーが発生しました: {str(e)}"

def extract_contacts_from_text(text):
    """テキストから連絡先情報を抽出"""
    contacts = {}
    
    # 電話番号パターン
    phone_patterns = [
        r'0\d{1,4}-\d{1,4}-\d{4}',
        r'0\d{9,10}',
        r'\+81\d{9,10}',
        r'090-\d{4}-\d{4}',
        r'080-\d{4}-\d{4}',
        r'070-\d{4}-\d{4}'
    ]
    
    phones = []
    for pattern in phone_patterns:
        phones.extend(re.findall(pattern, text))
    
    if phones:
        contacts['電話番号'] = list(set(phones))
    
    # メールアドレス
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)
    if emails:
        contacts['メールアドレス'] = list(set(emails))
    
    # URL
    urls = re.findall(r'https?://[^\s]+', text)
    if urls:
        contacts['URL'] = list(set(urls))
    
    return contacts

if api_key:
    # Gemini の設定
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-2.0-flash-exp')
    
    st.title("🔒 セキュリティチェッカー")
    st.write("詐欺・フィッシング対策のための包括的なセキュリティチェックツール")
    
    # タブで機能を分ける
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🌐 URLチェック", 
        "📱 スクリーンショット分析", 
        "📄 OCR + テキスト分析", 
        "✍️ 日本語チェック",
        "📞 連絡先検索"
    ])
    
    with tab1:
        st.header("🌐 URLセキュリティチェック")
        url_input = st.text_input("チェックしたいURLを入力してください：")
        
        if st.button("URLをチェック", key="url_check"):
            if url_input:
                with st.spinner("URLを分析中..."):
                    # 基本的な安全性チェック
                    safety_score, warnings = check_url_safety(url_input)
                    
                    col1, col2 = st.columns([1, 2])
                    
                    with col1:
                        # スコア表示
                        if safety_score >= 80:
                            st.success(f"🟢 安全度: {safety_score}/100")
                        elif safety_score >= 60:
                            st.warning(f"🟡 安全度: {safety_score}/100")
                        else:
                            st.error(f"🔴 安全度: {safety_score}/100")
                    
                    with col2:
                        # 警告一覧
                        if warnings:
                            st.write("**検出された問題:**")
                            for warning in warnings:
                                st.write(warning)
                        else:
                            st.write("✅ 基本的なチェックで問題は検出されませんでした")
                    
                    # Geminiによる詳細分析
                    gemini_prompt = f"""
                    以下のURLについて、詐欺・フィッシングサイトの可能性を分析してください：
                    URL: {url_input}
                    
                    以下の観点で分析してください：
                    1. ドメイン名の怪しさ
                    2. URL構造の特徴
                    3. 既知の詐欺パターンとの類似性
                    4. 総合的な危険度評価
                    
                    簡潔で分かりやすく日本語で回答してください。
                    """
                    
                    gemini_analysis = analyze_with_gemini(model, gemini_prompt)
                    st.write("**🤖 Gemini AI による詳細分析:**")
                    st.write(gemini_analysis)
    
    with tab2:
        st.header("📱 スクリーンショット分析")
        st.write("怪しいメッセージやサイトのスクリーンショットをアップロードして分析")
        
        uploaded_screenshot = st.file_uploader(
            "スクリーンショット画像をアップロード", 
            type=['png', 'jpg', 'jpeg'],
            key="screenshot"
        )
        
        if uploaded_screenshot:
            image = Image.open(uploaded_screenshot)
            st.image(image, caption="アップロードされた画像", use_container_width=True)
            
            if st.button("画像を分析", key="screenshot_analyze"):
                with st.spinner("画像を分析中..."):
                    analysis_prompt = """
                    この画像を詐欺・フィッシングの観点から分析してください。以下の点を確認してください：

                    1. 表示されているメッセージや内容の怪しさ
                    2. UI/UXデザインの特徴（偽装の可能性）
                    3. 表示されているURL、連絡先、金額などの情報
                    4. 緊急性を煽る表現や不安を誘う内容
                    5. 正規のサービスを装った偽装の可能性
                    6. 総合的な危険度評価（低・中・高）

                    日本語で詳しく分析結果を教えてください。
                    """
                    
                    analysis_result = analyze_with_gemini(model, analysis_prompt, image)
                    st.write("**🤖 スクリーンショット分析結果:**")
                    st.write(analysis_result)
    
    with tab3:
        st.header("📄 OCR + テキスト分析")
        
        # テキスト直接入力
        text_input = st.text_area("分析したいテキストを入力:", height=150)
        
        # 画像からのOCR
        st.write("または、画像からテキストを抽出:")
        uploaded_ocr = st.file_uploader(
            "テキストが含まれた画像をアップロード", 
            type=['png', 'jpg', 'jpeg'],
            key="ocr"
        )
        
        if uploaded_ocr:
            ocr_image = Image.open(uploaded_ocr)
            st.image(ocr_image, caption="OCR対象画像", use_container_width=True)
            
            if st.button("テキストを抽出", key="ocr_extract"):
                with st.spinner("テキストを抽出中..."):
                    ocr_prompt = """
                    この画像からテキストを正確に抽出してください。
                    日本語、英語、数字、記号をすべて読み取って、
                    元のレイアウトをできるだけ保持して返してください。
                    """
                    
                    extracted_text = analyze_with_gemini(model, ocr_prompt, ocr_image)
                    st.write("**抽出されたテキスト:**")
                    st.code(extracted_text)
                    text_input = extracted_text
        
        if text_input and st.button("テキストを分析", key="text_analyze"):
            with st.spinner("テキストを分析中..."):
                # 連絡先情報抽出
                contacts = extract_contacts_from_text(text_input)
                
                if contacts:
                    st.write("**📞 検出された連絡先情報:**")
                    for contact_type, contact_list in contacts.items():
                        st.write(f"**{contact_type}:**")
                        for contact in contact_list:
                            st.code(contact)
                
                # Gemini分析
                text_analysis_prompt = f"""
                以下のテキストを詐欺・フィッシングの観点から分析してください：

                テキスト:
                {text_input}

                分析項目：
                1. 詐欺的表現の検出（緊急性、恐怖心、利益誘導など）
                2. 不自然な日本語や翻訳ソフト特有の表現
                3. 金銭や個人情報を要求する内容
                4. 正規サービスを装った偽装の可能性
                5. 文法や表現の不自然さ
                6. 連絡先情報の妥当性
                7. 総合的な危険度評価

                日本語で詳細に分析してください。
                """
                
                analysis_result = analyze_with_gemini(model, text_analysis_prompt)
                st.write("**🤖 テキスト分析結果:**")
                st.write(analysis_result)
    
    with tab4:
        st.header("✍️ 日本語チェック")
        japanese_text = st.text_area("チェックしたい日本語テキストを入力:", height=150, key="jp_check")
        
        if japanese_text and st.button("日本語をチェック", key="japanese_check"):
            with st.spinner("日本語を分析中..."):
                japanese_check_prompt = f"""
                以下の日本語テキストの不自然さを詳細に分析してください：

                テキスト:
                {japanese_text}

                チェック項目：
                1. 文法的な誤り
                2. 不自然な語彙選択
                3. 翻訳ソフト特有の表現
                4. 敬語の誤用
                5. カタカナ表記の不自然さ
                6. 句読点の使い方
                7. 文体の一貫性
                8. ネイティブスピーカーが書いた可能性

                それぞれの問題点を具体的に指摘し、改善案も提示してください。
                最後に、このテキストがネイティブスピーカーによるものか、
                翻訳ソフトや外国人による可能性が高いかを判定してください。
                """
                
                japanese_analysis = analyze_with_gemini(model, japanese_check_prompt)
                st.write("**🤖 日本語分析結果:**")
                st.write(japanese_analysis)
    
    with tab5:
        st.header("📞 連絡先検索・調査")
        
        search_type = st.selectbox("検索タイプ", ["電話番号", "メールアドレス", "会社名", "ウェブサイト"])
        search_query = st.text_input(f"{search_type}を入力:")
        
        if search_query and st.button("検索・調査", key="contact_search"):
            with st.spinner("調査中..."):
                search_prompt = f"""
                以下の{search_type}について調査してください：
                {search_query}

                調査項目：
                1. この連絡先の一般的な評判や情報
                2. 詐欺や悪質業者としての報告の有無
                3. 正規の企業・サービスとの関連性
                4. インターネット上での言及状況
                5. 注意すべき点や危険性
                6. 信頼度の評価

                ※直接的な個人情報は避け、一般的に公開されている情報や
                詐欺対策の観点から有用な情報を提供してください。
                """
                
                search_result = analyze_with_gemini(model, search_prompt)
                st.write("**🤖 連絡先調査結果:**")
                st.write(search_result)
                
                st.warning("⚠️ この結果は参考情報です。最終的な判断は必ず複数の情報源で確認してください。")

else:
    st.warning("左のサイドバーでGoogle AI API キーを入力してください")
    st.info("""
    ## 🔒 セキュリティチェッカーの機能

    このアプリは以下の機能を提供します：

    ### 🌐 URLチェック
    - URLの安全性を多角的に分析
    - SSL証明書の確認
    - 詐欺サイトのパターン検出

    ### 📱 スクリーンショット分析
    - 怪しいメッセージやサイトの画像を分析
    - フィッシング詐欺の特徴を検出

    ### 📄 OCR + テキスト分析
    - 画像からテキストを抽出
    - 詐欺メッセージの特徴を分析
    - 連絡先情報の自動抽出

    ### ✍️ 日本語チェック
    - 不自然な日本語表現を検出
    - 翻訳ソフト特有の表現を識別

    ### 📞 連絡先検索
    - 電話番号やメールアドレスの調査
    - 悪質業者の可能性をチェック

    ## API キーの取得方法
    1. [Google AI Studio](https://aistudio.google.com/) にアクセス
    2. 「Get API key」をクリック
    3. 新しいプロジェクトでAPI キーを作成
    """)

# 使用上の注意
st.sidebar.markdown("""
---
## ⚠️ 使用上の注意

- このツールの結果は参考情報です
- 最終判断は複数の情報源で確認してください
- 個人情報の取り扱いには十分注意してください
- 疑わしい場合は専門機関に相談してください

## 📞 相談先
- 消費者ホットライン: 188
- 警察相談専用電話: #9110
- フィッシング対策協議会: https://www.antiphishing.jp/
""")
import streamlit as st

st.title("🎈 My new app")
st.write(
    "Let's start building! For help and inspiration, head over to [docs.streamlit.io](https://docs.streamlit.io/)."
)
