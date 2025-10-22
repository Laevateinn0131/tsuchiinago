import streamlit as st
import google.generativeai as genai
import requests
import re
import urllib.parse
from PIL import Image
import io
import base64
from urllib.parse import urlparse
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
import json
import re
from datetime import datetime
import time
import random
import os

# Gemini API (インストール必要: pip install google-generativeai)
try:
   import google.generativeai as genai
   GEMINI_AVAILABLE = True
except ImportError:
   GEMINI_AVAILABLE = False
   st.warning("⚠️ Gemini APIがインストールされていません。pip install google-generativeai を実行してください。")

# ページ設定
st.set_page_config(
   page_title="📞 AI電話番号チェッカー",
   page_icon="🤖",
   layout="wide"
)

# デフォルトのAPIキー（環境変数から取得、なければデフォルト値）
DEFAULT_API_KEY = os.getenv("GEMINI_API_KEY", "AIzaSyDuxrHGEiBATrTUQ6iqiZqe_oyNbNL58Ww")

# セッション状態の初期化
if 'check_history' not in st.session_state:
   st.session_state.check_history = []
if 'scam_database' not in st.session_state:
   st.session_state.scam_database = {
       "known_scam_numbers": [
           "03-1234-5678",
           "0120-999-999",
           "050-1111-2222",
           "090-1234-5678"
       ],
       "suspicious_prefixes": [
           "050", "070", "+675", "+234", "+1-876"
       ],
       "warning_patterns": [
           r"^0120", r"^0570", r"^0990", r"^\+.*"
       ],
       "safe_prefixes": ["110", "119", "118"]
   }
if 'monitoring' not in st.session_state:
   st.session_state.monitoring = False
if 'last_check' not in st.session_state:
   st.session_state.last_check = None
if 'gemini_api_key' not in st.session_state:
   st.session_state.gemini_api_key = DEFAULT_API_KEY
if 'ai_enabled' not in st.session_state:
   st.session_state.ai_enabled = False

def setup_gemini():
   """Gemini API設定"""
   if st.session_state.gemini_api_key and GEMINI_AVAILABLE:
       try:
           genai.configure(api_key=st.session_state.gemini_api_key)
           return True
       except Exception as e:
           st.error(f"Gemini API設定エラー: {str(e)}")
           return False
   return False

def analyze_with_gemini(number, basic_result):
   """Gemini AIによる高度な分析（caller_type追加）"""
   if not setup_gemini():
       return None
   
   try:
       model = genai.GenerativeModel('gemini-pro')
       caller_type_info = basic_result.get('caller_type', {})
       
       prompt = f"""
あなたは電話番号の専門家です。以下の情報から、この電話番号の詳細を分析してください。

電話番号: {number}
正規化: {basic_result['normalized']}
番号タイプ: {basic_result['details'][0] if basic_result['details'] else '不明'}
地域: {basic_result['details'][1] if len(basic_result['details']) > 1 else '不明'}

現在の判定:
- 発信者タイプ: {caller_type_info.get('type', '不明')}
- カテゴリ: {caller_type_info.get('category', '不明')}
- リスクレベル: {basic_result['risk_level']}

以下を分析してJSON形式で回答:
{{
   "caller_identification": {{
       "most_likely": "個人/一般企業/金融機関/公的機関/詐欺グループ/不明",
       "confidence": "高/中/低",
       "reasoning": "判定理由"
   }},
   "business_type": "具体的な業種（例: 通信販売、保険営業、アンケート調査など）",
   "ai_risk_assessment": "安全/注意/危険",
   "confidence_score": 0-100,
   "fraud_patterns": ["考えられる詐欺パターン"],
   "similar_cases": ["類似事例"],
   "recommendations": ["推奨行動"],
   "conversation_warnings": ["警戒すべき会話内容"],
   "summary": "総合分析（150文字程度）"
}}
"""
       
       response = model.generate_content(prompt)
       
       try:
           ai_result = json.loads(response.text)
           return ai_result
       except:
           return {
               "caller_identification": {
                   "most_likely": "不明",
                   "confidence": "低",
                   "reasoning": "分析失敗"
               },
               "business_type": "不明",
               "ai_risk_assessment": "不明",
               "confidence_score": 0,
               "fraud_patterns": [],
               "similar_cases": [],
               "recommendations": [],
               "conversation_warnings": [],
               "summary": response.text[:200]
           }
   except Exception as e:
       st.error(f"Gemini分析エラー: {str(e)}")
       return None

def analyze_conversation_with_gemini(conversation_text):
   """通話内容をGemini AIで分析"""
   if not setup_gemini():
       return None
   
   try:
       model = genai.GenerativeModel('gemini-pro')
       
       prompt = f"""
あなたは詐欺電話検出の専門家です。以下の通話内容を分析してください。

通話内容:
{conversation_text}

以下を分析してください:
1. 詐欺の可能性（0-100%）
2. 詐欺の手口の種類
3. 危険なキーワード
4. すぐに取るべき行動
5. 通報すべきかどうか

JSON形式で回答:
{{
   "scam_probability": 0-100,
   "fraud_type": "オレオレ詐欺/架空請求/など",
   "dangerous_keywords": ["キーワード1", "キーワード2"],
   "immediate_actions": ["行動1", "行動2"],
   "should_report": true/false,
   "explanation": "詳細な説明"
}}
"""
       
       response = model.generate_content(prompt)
       try:
           return json.loads(response.text)
       except:
           return {"explanation": response.text[:200]}
   except Exception as e:
       st.error(f"会話分析エラー: {str(e)}")
       return None

def identify_caller_type(number, normalized):
   """発信者タイプの詳細識別"""
   caller_info = {
       "type": "不明",
       "confidence": "低",
       "details": [],
       "category": "その他"
   }
   
   # 緊急番号
   if normalized in ["110", "119", "118"]:
       caller_info["type"] = "緊急通報番号"
       caller_info["confidence"] = "確実"
       caller_info["category"] = "公的機関"
       caller_info["details"].append("警察・消防・海上保安庁")
       return caller_info
   
   # 公的機関の代表番号パターン
   government_patterns = {
       "03-3581": "官公庁（霞が関周辺）",
       "03-5253": "厚生労働省・文部科学省エリア",
       "03-3580": "警察庁周辺",
       "03-5321": "都庁・都の機関",
       "06-6941": "大阪府庁周辺",
   }
   
   for prefix, org in government_patterns.items():
       if number.startswith(prefix):
           caller_info["type"] = "公的機関"
           caller_info["confidence"] = "高"
           caller_info["category"] = "公的機関"
           caller_info["details"].append(org)
           return caller_info
   
   # 銀行・金融機関
   bank_patterns = {
       "0120-86": "三菱UFJ銀行系",
       "0120-77": "三井住友銀行系",
       "0120-65": "みずほ銀行系",
       "0120-39": "ゆうちょ銀行系",
   }
   
   for prefix, bank in bank_patterns.items():
       if number.startswith(prefix):
           caller_info["type"] = "金融機関"
           caller_info["confidence"] = "中"
           caller_info["category"] = "一般企業"
           caller_info["details"].append(bank)
           caller_info["details"].append("⚠️ 本物か必ず確認してください")
           return caller_info
   
   # 番号タイプによる判定
   if normalized.startswith('0120') or normalized.startswith('0800'):
       caller_info["type"] = "企業カスタマーサポート"
       caller_info["confidence"] = "中"
       caller_info["category"] = "一般企業"
       caller_info["details"].append("フリーダイヤル（通話無料）")
       caller_info["details"].append("企業からの連絡が多い")
   elif normalized.startswith('0570'):
       caller_info["type"] = "企業ナビダイヤル"
       caller_info["confidence"] = "中"
       caller_info["category"] = "一般企業"
       caller_info["details"].append("通話料有料（高額になることも）")
       caller_info["details"].append("企業のサポートセンター等")
   elif normalized.startswith('050'):
       caller_info["type"] = "IP電話利用者"
       caller_info["confidence"] = "低"
       caller_info["category"] = "不明"
       caller_info["details"].append("個人/企業どちらも可能性あり")
       caller_info["details"].append("IP電話は匿名性が高い")
       caller_info["details"].append("⚠️ 詐欺に悪用されやすい")
   elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
       caller_info["type"] = "個人携帯電話"
       caller_info["confidence"] = "高"
       caller_info["category"] = "個人"
       caller_info["details"].append("個人契約の携帯電話")
       caller_info["details"].append("まれに法人契約もあり")
   elif normalized.startswith('020'):
       caller_info["type"] = "ポケベル・M2M"
       caller_info["confidence"] = "高"
       caller_info["category"] = "特殊"
       caller_info["details"].append("IoT機器等の通信")
   elif normalized.startswith('0'):
       area = identify_area(number)
       if area != "不明":
           caller_info["type"] = "固定電話（企業または個人宅）"
           caller_info["confidence"] = "中"
           caller_info["category"] = "企業または個人"
           caller_info["details"].append(f"地域: {area}")
           caller_info["details"].append("企業のオフィスまたは個人宅")
       else:
           caller_info["type"] = "固定電話"
           caller_info["confidence"] = "低"
           caller_info["category"] = "不明"
   elif number.startswith('+') or normalized.startswith('010'):
       caller_info["type"] = "国際電話"
       caller_info["confidence"] = "確実"
       caller_info["category"] = "国際"
       caller_info["details"].append("海外からの着信")
       caller_info["details"].append("⚠️ 国際詐欺に注意")
   
   return caller_info

def identify_area(number):
   """地域識別"""
   area_codes = {
       "03": "東京", "06": "大阪", "052": "名古屋",
       "011": "札幌", "092": "福岡", "075": "京都"
   }
   for code, area in area_codes.items():
       if number.startswith(code):
           return area
   return "不明"

def identify_number_type(normalized):
   """番号タイプ識別"""
   if normalized.startswith('0120') or normalized.startswith('0800'):
       return "フリーダイヤル"
   elif normalized.startswith('050'):
       return "IP電話"
   elif normalized.startswith('090') or normalized.startswith('080') or normalized.startswith('070'):
       return "携帯電話"
   elif normalized.startswith('0570'):
       return "ナビダイヤル"
   elif normalized.startswith('0'):
       return "固定電話"
   elif normalized.startswith('+'):
       return "国際電話"
   else:
       return "不明"

def analyze_phone_number(number, use_ai=False):
   """電話番号解析"""
   normalized = re.sub(r'[-\s()]+', '', number)
   
   result = {
       "original": number,
       "normalized": normalized,
       "risk_level": "安全",
       "warnings": [],
       "details": [],
       "recommendations": [],
       "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
       "ai_analysis": None,
       "caller_type": None
   }
   
   # 発信者タイプ識別
   caller_type = identify_caller_type(number, normalized)
   result["caller_type"] = caller_type
   
   # 緊急番号チェック
   if normalized in ["110", "119", "118"]:
       result["risk_level"] = "緊急"
       result["details"].append("✅ 緊急通報番号です")
       return result
   
   # 既知の詐欺番号チェック
   if number in st.session_state.scam_database["known_scam_numbers"]:
       result["risk_level"] = "危険"
       result["warnings"].append("🚨 既知の詐欺電話番号です！")
       result["recommendations"].append("❌ 絶対に応答しないでください")
       result["recommendations"].append("📞 着信拒否設定を推奨")
   
   # プレフィックスチェック
   for prefix in st.session_state.scam_database["suspicious_prefixes"]:
       if normalized.startswith(prefix):
           if result["risk_level"] == "安全":
               result["risk_level"] = "注意"
           result["warnings"].append(f"⚠️ 疑わしいプレフィックス: {prefix}")
           result["recommendations"].append("慎重に対応してください")
   
   # パターンチェック
   for pattern in st.session_state.scam_database["warning_patterns"]:
       if re.match(pattern, number):
           if result["risk_level"] == "安全":
               result["risk_level"] = "注意"
           result["warnings"].append("⚠️ 警戒が必要なパターンです")
   
   # 国際電話チェック
   if number.startswith('+') or normalized.startswith('010'):
       result["warnings"].append("🌍 国際電話です")
       result["recommendations"].append("身に覚えがない場合は応答しない")
       if result["risk_level"] == "安全":
           result["risk_level"] = "注意"
   
   # 詳細情報
   result["details"].append(f"📱 番号タイプ: {identify_number_type(normalized)}")
   result["details"].append(f"📍 地域: {identify_area(number)}")
   
   # 安全な場合の推奨事項
   if result["risk_level"] == "安全":
       result["recommendations"].append("✅ 特に問題は検出されませんでした")
       result["recommendations"].append("💡 不審な要求には注意してください")
   
   # AI分析
   if use_ai and st.session_state.ai_enabled:
       with st.spinner("🤖 AIが高度な分析を実行中..."):
           ai_result = analyze_with_gemini(number, result)
           if ai_result:
               result["ai_analysis"] = ai_result
               if ai_result.get("ai_risk_assessment") == "危険" and result["risk_level"] != "危険":
                   result["risk_level"] = "危険"
                   result["warnings"].append(f"🤖 AI判定: 危険 (信頼度 {ai_result.get('confidence_score', 0)}%)")
   
   # 履歴に追加
   st.session_state.check_history.append(result)
   return result

def display_result(result):
   """結果表示"""
   risk_colors = {
       "安全": "green", "注意": "orange",
       "危険": "red", "緊急": "blue"
   }
   risk_emoji = {
       "安全": "✅", "注意": "⚠️",
       "危険": "🚨", "緊急": "🚑"
   }
   
   color = risk_colors.get(result['risk_level'], "gray")
   emoji = risk_emoji.get(result['risk_level'], "❓")
   
   st.markdown(f"## {emoji} リスク判定: :{color}[{result['risk_level']}]")
   
   # 発信者タイプ情報
   if result.get('caller_type'):
       caller = result['caller_type']
       category_icons = {
           "個人": "👤", "一般企業": "🏢", "公的機関": "🏛️",
           "金融機関": "🏦", "国際": "🌍", "特殊": "⚙️",
           "不明": "❓", "その他": "📞"
       }
       icon = category_icons.get(caller['category'], "📞")
       
       st.info(f"""
       ### {icon} 発信者タイプ: **{caller['type']}**
       **カテゴリ**: {caller['category']}  
       **信頼度**: {caller['confidence']}
       """)
       
       if caller['details']:
           with st.expander("🔍 発信者詳細情報"):
               for detail in caller['details']:
                   st.markdown(f"- {detail}")
   
   col1, col2, col3 = st.columns(3)
   with col1:
       st.metric("📞 電話番号", result['original'])
   with col2:
       st.metric("🔢 正規化", result['normalized'])
   with col3:
       st.metric("🕐 チェック時刻", result['timestamp'])
   
   st.markdown("---")
   
   # AI分析結果
   if result.get('ai_analysis'):
       ai = result['ai_analysis']
       st.success("### 🤖 Gemini AI 高度分析")
       
       if ai.get('caller_identification'):
           caller_id = ai['caller_identification']
           col1, col2, col3 = st.columns(3)
           with col1:
               st.metric("AI判定", caller_id.get('most_likely', '不明'))
           with col2:
               st.metric("AI信頼度", f"{ai.get('confidence_score', 0)}%")
           with col3:
               business = ai.get('business_type', '不明')
               st.metric("業種", business if len(business) < 20 else business[:17]+"...")
           
           if caller_id.get('reasoning'):
               st.info(f"**判定理由**: {caller_id['reasoning']}")
       
       if ai.get('summary'):
           st.success(f"**📝 AI総合分析**: {ai['summary']}")
       
       if ai.get('fraud_patterns'):
           with st.expander("🎯 想定される詐欺パターン"):
               for pattern in ai['fraud_patterns']:
                   st.markdown(f"- {pattern}")
       
       if ai.get('similar_cases'):
           with st.expander("📋 類似詐欺事例"):
               for case in ai['similar_cases']:
                   st.markdown(f"- {case}")
       
       if ai.get('conversation_warnings'):
           with st.expander("⚠️ 会話で警戒すべきポイント"):
               for warning in ai['conversation_warnings']:
                   st.markdown(f"- {warning}")
       
       st.markdown("---")
   
   # 警告
   if result['warnings']:
       st.error("### ⚠️ 警告")
       for warning in result['warnings']:
           st.markdown(f"- {warning}")
       st.markdown("")
   
   # 詳細情報
   if result['details']:
       st.info("### 📋 詳細情報")
       for detail in result['details']:
           st.markdown(f"- {detail}")
       st.markdown("")
   
   # 推奨事項
   if result['recommendations']:
       if result['risk_level'] == "危険":
           st.error("### 💡 推奨事項")
       else:
           st.success("### 💡 推奨事項")
       for rec in result['recommendations']:
           st.markdown(f"- {rec}")
       
       if result.get('ai_analysis') and result['ai_analysis'].get('recommendations'):
           st.markdown("**🤖 AIからの追加推奨:**")
           for rec in result['ai_analysis']['recommendations']:
               st.markdown(f"- {rec}")

def show_stats():
   """統計情報表示"""
   total = len(st.session_state.check_history)
   dangerous = sum(1 for r in st.session_state.check_history if r['risk_level'] == '危険')
   warning = sum(1 for r in st.session_state.check_history if r['risk_level'] == '注意')
   safe = sum(1 for r in st.session_state.check_history if r['risk_level'] == '安全')
   
   col1, col2, col3, col4 = st.columns(4)
   col1.metric("📊 総チェック数", total)
   col2.metric("🚨 詐欺検出", dangerous)
   col3.metric("⚠️ 警告", warning)
   col4.metric("✅ 安全", safe)

# メインUI
st.title("🤖 Gemini AI搭載 電話番号チェッカー")
st.markdown("Google Gemini AIによる高度な詐欺電話検出システム")

# サイドバー
with st.sidebar:
   st.header("🛠️ メニュー")
   
   # Gemini API設定
   with st.expander("🔑 Gemini API設定", expanded=not st.session_state.ai_enabled):
       api_key_input = st.text_input(
           "Gemini API Key",
           type="password",
           value=st.session_state.gemini_api_key,
           help="https://makersuite.google.com/app/apikey から取得"
       )
       
       if st.button("API Key保存"):
           st.session_state.gemini_api_key = api_key_input
           if setup_gemini():
               st.session_state.ai_enabled = True
               st.success("✅ Gemini AI有効化！")
           else:
               st.session_state.ai_enabled = False
               st.error("❌ API Key無効")
       
       # 自動でAPI設定を試行
       if st.session_state.gemini_api_key and not st.session_state.ai_enabled:
           if setup_gemini():
               st.session_state.ai_enabled = True
       
       st.session_state.ai_enabled = st.checkbox(
           "AI分析を有効化",
           value=st.session_state.ai_enabled,
           disabled=not st.session_state.gemini_api_key
       )
       
       if st.session_state.ai_enabled:
           st.success("🤖 AI分析: ON")
       else:
           st.info("🤖 AI分析: OFF")
   
   st.markdown("---")
   
   page = st.radio(
       "ページ選択",
       ["🔍 番号チェック", "💬 会話分析", "📊 統計情報", "🗄️ データベース", "ℹ️ 使い方"]
   )
   
   st.markdown("---")
   st.subheader("📈 簡易統計")
   show_stats()
   
   st.markdown("---")
   st.subheader("👁️ リアルタイム監視")
   if st.button("🟢 監視開始" if not st.session_state.monitoring else "🔴 監視停止"):
       st.session_state.monitoring = not st.session_state.monitoring
   
   if st.session_state.monitoring:
       st.success("監視中...")
       if st.button("🎲 着信シミュレート"):
           test_numbers = ["090-1234-5678", "03-5555-6666", "050-9999-8888", "+1-876-555-1234"]
           test_number = random.choice(test_numbers)
           st.session_state.last_check = analyze_phone_number(test_number, use_ai=st.session_state.ai_enabled)
           st.rerun()
   else:
       st.info("停止中")

# メインコンテンツ
if page == "🔍 番号チェック":
   st.header("🔍 AI電話番号チェック")
   
   col1, col2 = st.columns([3, 1])
   with col1:
       phone_input = st.text_input(
           "電話番号を入力してください",
           placeholder="例: 090-1234-5678, 03-1234-5678, +81-90-1234-5678",
           key="phone_input"
       )
   with col2:
       st.markdown("<br>", unsafe_allow_html=True)
       check_btn = st.button("🔍 チェック", use_container_width=True)
   
   if check_btn and phone_input:
       with st.spinner("解析中..."):
           result = analyze_phone_number(phone_input, use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
       
       if result['risk_level'] == "危険":
           st.markdown("### 🚨🚨🚨 警告！ 🚨🚨🚨")
   
   if st.session_state.last_check:
       st.markdown("---")
       st.subheader("📋 チェック結果")
       display_result(st.session_state.last_check)
   
   st.markdown("---")
   st.subheader("🧪 サンプル番号でテスト")
   sample_col1, sample_col2, sample_col3, sample_col4 = st.columns(4)
   
   with sample_col1:
       if st.button("✅ 安全な番号"):
           result = analyze_phone_number("03-5555-6666", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()
   with sample_col2:
       if st.button("⚠️ 注意が必要"):
           result = analyze_phone_number("050-1111-2222", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()
   with sample_col3:
       if st.button("🚨 詐欺番号"):
           result = analyze_phone_number("090-1234-5678", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()
   with sample_col4:
       if st.button("🌍 国際詐欺"):
           result = analyze_phone_number("+1-876-555-1234", use_ai=st.session_state.ai_enabled)
           st.session_state.last_check = result
           st.rerun()

elif page == "💬 会話分析":
   st.header("💬 通話内容AI分析")
   st.markdown("通話中の会話内容をAIで分析し、詐欺の可能性を判定します")
   
   if not st.session_state.ai_enabled:
       st.warning("⚠️ この機能を使用するにはGemini APIを有効化してください")
   
   conversation_text = st.text_area(
       "通話内容を入力してください",
       placeholder="例:\n相手: お客様の口座が不正利用されています\n私: どういうことですか？\n相手: すぐにキャッシュカードの番号を教えてください...",
       height=200
   )
   
   if st.button("🤖 AI分析実行", disabled=not st.session_state.ai_enabled):
       if conversation_text:
           with st.spinner("🤖 AIが会話内容を分析中..."):
               analysis = analyze_conversation_with_gemini(conversation_text)
               if analysis:
                   st.markdown("---")
                   st.subheader("📋 AI分析結果")
                   
                   col1, col2 = st.columns(2)
                   with col1:
                       scam_prob = analysis.get('scam_probability', 0)
                       st.metric("詐欺可能性", f"{scam_prob}%")
                   with col2:
                       fraud_type = analysis.get('fraud_type', '不明')
                       st.metric("詐欺タイプ", fraud_type)
                   
                   if analysis.get('dangerous_keywords'):
                       st.error("### ⚠️ 危険なキーワード検出")
                       for keyword in analysis['dangerous_keywords']:
                           st.markdown(f"- `{keyword}`")
                   
                   if analysis.get('immediate_actions'):
                       st.warning("### 🚨 すぐに取るべき行動")
                       for action in analysis['immediate_actions']:
                           st.markdown(f"- {action}")
                   
                   if analysis.get('should_report'):
                       st.error("### 📞 警察への通報を推奨します")
                       st.markdown("**#9110（警察相談専用電話）** に連絡してください")
                   
                   if analysis.get('explanation'):
                       st.info(f"**詳細説明**: {analysis['explanation']}")
       else:
           st.warning("通話内容を入力してください")

elif page == "📊 統計情報":
   st.header("📊 統計情報")
   show_stats()
   
   st.markdown("---")
   st.subheader("📜 チェック履歴")
   
   if st.session_state.check_history:
       for i, record in enumerate(reversed(st.session_state.check_history[-10:]), 1):
           ai_badge = "🤖" if record.get('ai_analysis') else ""
           with st.expander(f"{i}. {ai_badge} {record['original']} - {record['risk_level']} ({record['timestamp']})"):
               display_result(record)
   else:
       st.info("まだチェック履歴がありません")
   
   if st.button("🗑️ 履歴をクリア"):
       st.session_state.check_history = []
       st.success("履歴をクリアしました")
       st.rerun()

elif page == "🗄️ データベース":
   st.header("🗄️ 詐欺電話データベース")
   
   tab1, tab2 = st.tabs(["既知の詐欺番号", "疑わしいプレフィックス"])
   
   with tab1:
       st.subheader("🚨 既知の詐欺番号")
       for i, number in enumerate(st.session_state.scam_database["known_scam_numbers"], 1):
           st.markdown(f"{i}. `{number}`")
       
       st.markdown("---")
       with st.form("add_scam_number"):
           new_number = st.text_input("新しい詐欺番号を追加")
           if st.form_submit_button("➕ 追加"):
               if new_number and new_number not in st.session_state.scam_database["known_scam_numbers"]:
                   st.session_state.scam_database["known_scam_numbers"].append(new_number)
                   st.success(f"✅ {new_number} を追加しました")
                   st.rerun()
   
   with tab2:
       st.subheader("⚠️ 疑わしいプレフィックス")
       for prefix in st.session_state.scam_database["suspicious_prefixes"]:
           st.markdown(f"- `{prefix}`")

else:  # 使い方
   st.header("ℹ️ 使い方ガイド")
   st.markdown("""
   ## 🤖 Gemini AI搭載電話番号チェッカー
   
   ### 🚀 クイックスタート
   
   1. **APIキーは設定済み** - すぐに使えます！
   2. サイドバーで「AI分析を有効化」にチェック
   3. 電話番号を入力して「チェック」
   
   ### 🆕 新機能: 発信者タイプ判定
   
   このアプリは電話番号から**誰からの電話か**を自動判定します！
   
   #### 📊 判定できる発信者タイプ
   
   | アイコン | タイプ | 説明 |
   |---------|--------|------|
   | 👤 | 個人 | 携帯電話（090/080/070） |
   | 🏢 | 一般企業 | フリーダイヤル、固定電話 |
   | 🏛️ | 公的機関 | 官公庁、警察、消防 |
   | 🏦 | 金融機関 | 銀行のカスタマーサポート |
   | 🌍 | 国際 | 海外からの着信 |
   | ⚙️ | 特殊 | IoT、M2M通信 |
   | ❓ | 不明 | 判定できない番号 |
   
   ### 🤖 AI機能の活用
   
   1. **高度な判定**
      - AI判定: 個人/企業/詐欺グループ
      - 業種: 通信販売、保険営業など
      - 判定理由の詳細説明
   
   2. **会話内容の分析**
      - 「💬 会話分析」ページで使用
      - 詐欺の可能性をパーセントで表示
      - 危険なキーワードを検出
   
   ### 🔍 基本的な使い方
   
   1. **番号チェック**
      - 電話番号を入力
      - 「チェック」ボタンをクリック
      - 発信者タイプとリスクを確認
   
   2. **リアルタイム監視**
      - サイドバーの「監視開始」をクリック
      - 着信シミュレートでテスト可能
   
   ### 🎯 リスクレベルの意味
   
   - **✅ 安全**: 特に問題なし
   - **⚠️ 注意**: 疑わしい特徴あり
   - **🚨 危険**: 詐欺の可能性が高い
   - **🚑 緊急**: 緊急通報番号
   
   ### 💡 見分け方のコツ
   
   #### 詐欺電話の特徴
   - 📱 050（IP電話）が多い
   - 🌍 国際電話（+で始まる）
   - 💰 金銭・個人情報を要求
   - 🚨 緊急性を装う
   - 😱 脅迫的な言動
   
   ### 🛡️ 対策方法
   
   1. **予防**
      - 知らない番号には出ない
      - 留守番電話で確認
      - 着信拒否設定を活用
   
   2. **対応中**
      - 個人情報は教えない
      - お金の話が出たら即切る
      - 録音すると伝える
   
   3. **事後**
      - 怪しいと思ったらデータベースに追加
      - このアプリで番号をチェック
      - 警察に相談（#9110）
   
   ### 📞 相談窓口
   
   - **警察相談**: #9110
   - **消費者ホットライン**: 188
   - **金融庁**: 0570-016811
   
   ### 🔒 プライバシーとセキュリティ
   
   - ✅ チェックした番号はローカルに保存
   - ✅ AI分析もプライバシー保護
   - ⚠️ APIキーは安全に管理
   
   """)
   
   st.info("💡 このアプリは継続的に改善されています。フィードバックをお待ちしています！")

# フッター
st.markdown("---")
st.caption("⚠️ このアプリは詐欺電話対策の補助ツールです。最終的な判断はご自身で行ってください。")
#ページ設定
st.set_page_config(page_title="🎣 フィッシング詐欺対策アプリ", page_icon="🛡️", layout="wide")
 
# メールサンプルデータ
quiz_samples = [
    {
        "subject": "【重要】あなたのアカウントが一時停止されました",
        "content": "お客様のアカウントに不審なアクセスが検出されました。以下のリンクから確認してください。\n→ http://security-update-login.com",
        "is_phishing": True,
        "explanation": "正規のドメインではなく、不審なURLを使用しています。"
    },
    {
        "subject": "【Amazon】ご注文ありがとうございます",
        "content": "ご注文いただいた商品は10月12日に発送されます。ご利用ありがとうございます。",
        "is_phishing": False,
        "explanation": "内容は自然で、URLも含まれていません。正規の連絡の可能性が高いです。"
    },
    {
        "subject": "【Apple ID】アカウント情報の確認が必要です",
        "content": "セキュリティのため、以下のURLから24時間以内に情報を更新してください。\n→ http://apple.login-check.xyz",
        "is_phishing": True,
        "explanation": "URLが公式のAppleドメインではありません。典型的なフィッシングサイトの形式です。"
    },
    {
        "subject": "【楽天】ポイント還元のお知らせ",
        "content": "キャンペーンにより、300ポイントを付与しました。楽天市場をご利用いただきありがとうございます。",
        "is_phishing": False,
        "explanation": "不自然なURLや情報要求がなく、自然な表現です。"
    },
]
 
# セッション状態の初期化
if 'quiz_index' not in st.session_state:
    st.session_state.quiz_index = 0
if 'score' not in st.session_state:
    st.session_state.score = 0
if 'quiz_order' not in st.session_state:
    st.session_state.quiz_order = random.sample(range(len(quiz_samples)), len(quiz_samples))
 
# メニュー
menu = st.sidebar.radio("📚 メニュー", ["🔍 クイズで学ぶ", "📖 詐欺パターン図鑑", "✅ チェックリスト", "ℹ️ アプリについて"])
 
# -----------------------------------------
# クイズページ
# -----------------------------------------
# -----------------------------------------
# クイズページ（改良版: 次へボタンで進行）
# -----------------------------------------
# クイズ（仮）
if menu == "🔍 クイズで学ぶ":
    st.title("🎣 フィッシングメールを見抜け！クイズ形式で学ぶ")
 
    if 'answered' not in st.session_state:
        st.session_state.answered = False
 
    index = st.session_state.quiz_order[st.session_state.quiz_index]
    quiz = quiz_samples[index]
 
    st.subheader(f"✉️ 件名: {quiz['subject']}")
    st.code(quiz['content'], language='text')
 
    if not st.session_state.answered:
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🚨 フィッシングメールだと思う"):
                st.session_state.answered = True
                if quiz["is_phishing"]:
                    st.success("✅ 正解です！これはフィッシングメールです。")
                    st.session_state.score += 1
                else:
                    st.error("❌ 不正解。これは正規のメールの可能性があります。")
                st.info(f"💡 解説: {quiz['explanation']}")
        with col2:
            if st.button("✅ 安全なメールだと思う"):
                st.session_state.answered = True
                if not quiz["is_phishing"]:
                    st.success("✅ 正解です！これは正規のメールです。")
                    st.session_state.score += 1
                else:
                    st.error("❌ 不正解。これはフィッシングの可能性があります。")
                st.info(f"💡 解説: {quiz['explanation']}")
    else:
        st.info(f"💡 解説: {quiz['explanation']}")
        if st.button("➡️ 次へ"):
            st.session_state.quiz_index += 1
            st.session_state.answered = False
            if st.session_state.quiz_index >= len(quiz_samples):
                st.session_state.quiz_index = len(quiz_samples)
                st.rerun()
 
    if st.session_state.quiz_index >= len(quiz_samples):
        st.markdown("---")
        st.success(f"🎉 クイズ終了！あなたのスコア: {st.session_state.score} / {len(quiz_samples)}")
        if st.button("🔄 もう一度挑戦する"):
            st.session_state.quiz_index = 0
            st.session_state.score = 0
            st.session_state.quiz_order = random.sample(range(len(quiz_samples)), len(quiz_samples))
            st.session_state.answered = False
 
 
    # クイズ終了
    if st.session_state.quiz_index >= len(quiz_samples):
        st.markdown("---")
        st.success(f"🎉 クイズ終了！あなたのスコア: {st.session_state.score} / {len(quiz_samples)}")
        if st.button("🔄 もう一度挑戦する"):
            st.session_state.quiz_index = 0
            st.session_state.score = 0
            st.session_state.quiz_order = random.sample(range(len(quiz_samples)), len(quiz_samples))
 
# -----------------------------------------
# パターン図鑑ページ
# -----------------------------------------
elif menu == "📖 詐欺パターン図鑑":
    st.title("📖 フィッシング詐欺パターン図鑑")
    st.markdown("よくある詐欺手口を知って、だまされない力をつけましょう。")
 
    patterns = [
        {"title": "アカウント停止系詐欺", "desc": "『あなたのアカウントは一時停止されました』という文言で焦らせ、偽のログインページに誘導します。"},
        {"title": "ポイント還元詐欺", "desc": "『ポイントがもらえる』『キャンペーンに当選』などでクリックを促すが、実際は情報を盗む目的です。"},
        {"title": "荷物の再配達詐欺", "desc": "『不在のため荷物を預かっています』というSMSで偽サイトに誘導。"},
        {"title": "AppleやAmazonを騙る詐欺", "desc": "実在する大手企業を装って、情報入力を促すリンクを送ってきます。"},
    ]
    for p in patterns:
        with st.expander(f"🔍 {p['title']}"):
            st.write(p['desc'])
 
# -----------------------------------------
# チェックリストページ
# -----------------------------------------
elif menu == "✅ チェックリスト":
    st.title("✅ フィッシングメール チェックリスト")
    st.markdown("怪しいメールを受け取ったら、以下の項目を確認しましょう。")
 
    checklist = [
        "送信者のメールアドレスが正規のものか？",
        "URLが企業の公式ドメインか？（例: amazon.co.jp）",
        "緊急性を煽る文言が使われていないか？",
        "個人情報やクレジットカード情報の入力を求められていないか？",
        "不自然な日本語、翻訳調の文章ではないか？",
        "リンクをホバーして実際のURLを確認したか？",
        "添付ファイルが怪しくないか？"
    ]
    for item in checklist:
        st.checkbox(item)
 
# -----------------------------------------
# アプリ情報ページ
# -----------------------------------------
else:
    st.title("ℹ️ アプリについて")
    st.markdown("""
    このアプリは、情報リテラシー向上のために開発された学習ツールです。  
    実際の詐欺手口に近い例を元に、ユーザーが安全に学べるように設計されています。
 
    ### 🎯 目的
    - フィッシング詐欺を自力で見抜く力をつける
    - クイズ形式で楽しく学習
    - よくある手口・対策方法の理解
 
    ### 📦 技術
    - Python + Streamlit
    - ローカル動作 or 社内教育用途
 
    ### ⚠️ 注意
    - このアプリは学習用です。実際のメール判別は慎重に行ってください。
    """)
    st.success("開発者：あなたの名前 / 学校 / 会社 など")
    # AI分析
    if ai_check and url_input:
        if not api_key:
            st.error("❌ AI分析にはGemini APIキーが必要です（サイドバーで設定）")
        else:
            with st.spinner("🤖 AIが分析中..."):
                try:
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel('gemini-1.5-flash')
                   
                    prompt = f"""以下のURLがフィッシング詐欺サイトである可能性を分析してください。
URL: {url_input}
 
以下の形式でJSON形式で回答してください：
{{
  "risk_level": "high/medium/low",
  "risk_score": 0-100の数値,
  "is_suspicious": true/false,
  "indicators": ["疑わしい点のリスト"],
  "recommendation": "ユーザーへの推奨アクション",
  "summary": "分析結果の簡潔な要約"
}}"""
                   
                    response = model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.2,
                            max_output_tokens=1000,
                        )
                    )
                   
                    json_match = re.search(r'\{[\s\S]*\}', response.text)
                    if json_match:
                        result = json.loads(json_match.group())
                       
                        st.markdown("---")
                        st.subheader("📊 AI分析結果")
                       
                        if result['risk_level'] == 'high':
                            st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        elif result['risk_level'] == 'medium':
                            st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                       
                        st.progress(result['risk_score'] / 100)
                       
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.subheader("🔍 検出された疑わしい点")
                            for i, indicator in enumerate(result['indicators'], 1):
                                st.markdown(f"{i}. {indicator}")
                       
                        with col_b:
                            st.subheader("💡 推奨アクション")
                            st.info(result['recommendation'])
                    else:
                        st.error("❌ 分析結果の解析に失敗しました")
                except Exception as e:
                    st.error(f"❌ エラーが発生しました: {str(e)}")
 
# タブ2: メールチェック
with tab2:
    st.header("📧 メール内容チェック")
   
    col1, col2 = st.columns([2, 1])
   
    with col1:
        email_input = st.text_area(
            "メール本文を入力",
            placeholder="メールの内容を貼り付けてください",
            height=300
        )
       
        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            email_local = st.button("🔍 ローカル分析（メール）", type="primary", use_container_width=True)
        with col_btn2:
            email_ai = st.button("🤖 AI分析（メール）", use_container_width=True)
   
    with col2:
        st.info("""
        **チェックポイント:**
        - 緊急性を煽っていないか
        - 個人情報を求めていないか
        - 不自然な日本語はないか
        - リンク先が正規サイトか
        - 疑わしいキーワードがないか
        """)
   
    # ローカル分析
    if email_local and email_input:
        with st.spinner("🔍 分析中..."):
            result = analyze_email_local(email_input)
           
            st.markdown("---")
            st.subheader("📊 分析結果")
           
            if result['risk_level'] == '危険':
                st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>このメールは詐欺の可能性が高いです！</p></div>', unsafe_allow_html=True)
            elif result['risk_level'] == '注意':
                st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>注意が必要です。慎重に確認してください。</p></div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>このメールは比較的安全です。</p></div>', unsafe_allow_html=True)
           
            st.progress(result['risk_score'] / 100)
           
            col_a, col_b = st.columns(2)
            with col_a:
                st.subheader("⚠️ 警告")
                if result['warnings']:
                    for warning in result['warnings']:
                        st.warning(warning)
                else:
                    st.success("特に問題は検出されませんでした")
           
            with col_b:
                st.subheader("📋 詳細情報")
                for detail in result['details']:
                    st.text(detail)
   
    # AI分析
    if email_ai and email_input:
        if not api_key:
            st.error("❌ AI分析にはGemini APIキーが必要です")
        else:
            with st.spinner("🤖 AIが分析中..."):
                try:
                    genai.configure(api_key=api_key)
                    model = genai.GenerativeModel('gemini-1.5-flash')
                   
                    prompt = f"""以下のメール内容がフィッシング詐欺である可能性を分析してください。
メール内容:
{email_input}
 
以下の形式でJSON形式で回答してください：
{{
  "risk_level": "high/medium/low",
  "risk_score": 0-100の数値,
  "is_suspicious": true/false,
  "indicators": ["疑わしい点のリスト"],
  "recommendation": "ユーザーへの推奨アクション",
  "summary": "分析結果の簡潔な要約"
}}"""
                   
                    response = model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.2,
                            max_output_tokens=1000,
                        )
                    )
                   
                    json_match = re.search(r'\{[\s\S]*\}', response.text)
                    if json_match:
                        result = json.loads(json_match.group())
                       
                        st.markdown("---")
                        st.subheader("📊 AI分析結果")
                       
                        if result['risk_level'] == 'high':
                            st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        elif result['risk_level'] == 'medium':
                            st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                        else:
                            st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)
                       
                        st.progress(result['risk_score'] / 100)
                       
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.subheader("🔍 検出された疑わしい点")
                            for i, indicator in enumerate(result['indicators'], 1):
                                st.markdown(f"{i}. {indicator}")
                       
                        with col_b:
                            st.subheader("💡 推奨アクション")
                            st.info(result['recommendation'])
                except Exception as e:
                    st.error(f"❌ エラーが発生しました: {str(e)}")
 
# タブ3: 通報・共有
with tab3:
    st.header("📢 怪しいサイト・メールを通報")
   
    with st.form("report_form"):
        report_url = st.text_input("URL", placeholder="https://suspicious-site.com")
        report_detail = st.text_area("詳細情報", placeholder="どのような詐欺の疑いがあるか説明してください", height=150)
        submitted = st.form_submit_button("📢 通報する", type="primary")
       
        if submitted:
            if report_url:
                report = {
                    "url": report_url,
                    "detail": report_detail,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                st.session_state.reported_sites.append(report)
                st.success("✅ 通報ありがとうございます！情報はデータベースに追加されました。")
            else:
                st.error("❌ URLを入力してください")
   
    st.markdown("---")
    st.subheader("📋 最近の通報情報")
   
    if st.session_state.reported_sites:
        for i, report in enumerate(reversed(st.session_state.reported_sites[-10:]), 1):
            with st.expander(f"🚨 通報 #{len(st.session_state.reported_sites) - i + 1} - {report['url'][:50]}..."):
                st.text(f"日時: {report['timestamp']}")
                st.text(f"URL: {report['url']}")
                st.text(f"詳細: {report['detail']}")
    else:
        st.info("まだ通報はありません")
 
# タブ4: 脅威情報
with tab4:
    st.header("⚠️ 脅威情報データベース")
   
    col1, col2 = st.columns([3, 1])
    with col1:
        st.text(f"最終更新: {st.session_state.last_update}")
    with col2:
        if st.button("🔄 更新", use_container_width=True):
            # 通報されたサイトをデータベースに追加
            for report in st.session_state.reported_sites:
                domain = urlparse(report['url']).netloc
                if domain and domain not in st.session_state.threat_database["dangerous_domains"]:
                    st.session_state.threat_database["dangerous_domains"].append(domain)
           
            st.session_state.last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            st.success("✅ データベースを更新しました！")
            time.sleep(1)
            st.rerun()
   
    st.markdown("---")
   
    col1, col2 = st.columns(2)
   
    with col1:
        st.subheader("🚫 危険なドメイン")
        for i, domain in enumerate(st.session_state.threat_database["dangerous_domains"], 1):
            st.markdown(f'<div class="threat-item">{i}. {domain}</div>', unsafe_allow_html=True)
   
    with col2:
        st.subheader("🔍 疑わしいキーワード")
        for i, keyword in enumerate(st.session_state.threat_database["suspicious_keywords"], 1):
            st.markdown(f'<div class="threat-item">{i}. {keyword}</div>', unsafe_allow_html=True)
 
# フッター
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem;">
    <p>⚠️ このツールは補助的なものです。最終的な判断は慎重に行ってください。</p>
    <p>💡 ローカル分析は無料、AI分析にはGemini APIキーが必要です</p>
    <p>Powered by Google Gemini AI & Local Threat Database</p>
</div>
""", unsafe_allow_html=True)
import streamlit as st

import json

import re

from datetime import datetime

from urllib.parse import urlparse

import time

# Gemini API

try:

    import google.generativeai as genai

    GEMINI_AVAILABLE = True

except ImportError:

    GEMINI_AVAILABLE = False

# ページ設定

st.set_page_config(

    page_title="フィッシング詐欺検知アプリ",

    page_icon="🛡️",

    layout="wide"

)

# セッション状態の初期化

if 'threat_database' not in st.session_state:

    st.session_state.threat_database = {

        "dangerous_domains": [

            "paypal-secure-login.com",

            "amazon-verify.net",

            "apple-support-id.com",

            "microsoft-security.net",

            "google-verify-account.com"

        ],

        "suspicious_keywords": [

            "verify account", "urgent action", "suspended",

            "confirm identity", "アカウント確認", "緊急",

            "本人確認", "パスワード更新", "セキュリティ警告"

        ],

        "dangerous_patterns": [

            r"http://[^/]*\.(tk|ml|ga|cf|gq)",

            r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}",

            r"https?://[^/]*-[^/]*(login|signin|verify)",

        ]

    }

if 'reported_sites' not in st.session_state:

    st.session_state.reported_sites = []

if 'last_update' not in st.session_state:

    st.session_state.last_update = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# カスタムCSS

st.markdown("""
<style>

    .main-header {

        text-align: center;

        padding: 2rem 0;

        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);

        color: white;

        border-radius: 10px;

        margin-bottom: 2rem;

    }

    .risk-high {

        background-color: #fee2e2;

        border-left: 5px solid #dc2626;

        padding: 1rem;

        border-radius: 5px;

        margin: 1rem 0;

    }

    .risk-medium {

        background-color: #fef3c7;

        border-left: 5px solid #f59e0b;

        padding: 1rem;

        border-radius: 5px;

        margin: 1rem 0;

    }

    .risk-low {

        background-color: #d1fae5;

        border-left: 5px solid #10b981;

        padding: 1rem;

        border-radius: 5px;

        margin: 1rem 0;

    }

    .threat-item {

        background-color: #f9fafb;

        padding: 0.5rem;

        margin: 0.3rem 0;

        border-radius: 3px;

        border-left: 3px solid #6366f1;

    }
</style>

""", unsafe_allow_html=True)

# ヘッダー

st.markdown("""
<div class="main-header">
<h1>🛡️ フィッシング詐欺検知アプリ</h1>
<p>AIと脅威データベースで怪しいURLやメールを分析</p>
</div>

""", unsafe_allow_html=True)

# URLチェック関数

def analyze_url_local(url):

    """ローカルデータベースでURL解析"""

    results = {

        "url": url,

        "risk_level": "安全",

        "risk_score": 10,

        "warnings": [],

        "details": []

    }

    try:

        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        if not domain:

            results["risk_level"] = "エラー"

            results["risk_score"] = 0

            results["warnings"].append("❌ 有効なURLではありません")

            return results

        # 危険ドメインチェック

        if any(d in domain for d in st.session_state.threat_database["dangerous_domains"]):

            results["risk_level"] = "危険"

            results["risk_score"] = 95

            results["warnings"].append("⚠️ 既知の詐欺サイトです！直ちにアクセスを中止してください")

        # パターンマッチング

        for pattern in st.session_state.threat_database["dangerous_patterns"]:

            if re.search(pattern, url):

                if results["risk_level"] == "安全":

                    results["risk_level"] = "注意"

                    results["risk_score"] = 60

                results["warnings"].append("⚠️ 疑わしいURLパターンを検出")

                break

        # HTTPSチェック

        if parsed.scheme == "http":

            results["warnings"].append("⚠️ HTTPSではありません（通信が暗号化されていません）")

            if results["risk_level"] == "安全":

                results["risk_level"] = "注意"

                results["risk_score"] = 40

        # 短縮URLチェック

        short_domains = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]

        if any(s in domain for s in short_domains):

            results["warnings"].append("ℹ️ 短縮URLです。実際のリンク先を確認してください")

        # 詳細情報

        results["details"].append(f"ドメイン: {domain}")

        results["details"].append(f"プロトコル: {parsed.scheme}")

        results["details"].append(f"パス: {parsed.path or '/'}")

    except Exception as e:

        results["risk_level"] = "エラー"

        results["risk_score"] = 0

        results["warnings"].append(f"❌ URL解析エラー: {str(e)}")

    return results

def analyze_email_local(content):

    """ローカルデータベースでメール解析"""

    results = {

        "risk_level": "安全",

        "risk_score": 10,

        "warnings": [],

        "details": []

    }

    # キーワードチェック

    found_keywords = []

    for keyword in st.session_state.threat_database["suspicious_keywords"]:

        if keyword.lower() in content.lower():

            found_keywords.append(keyword)

    if found_keywords:

        results["risk_level"] = "注意"

        results["risk_score"] = 50

        results["warnings"].append(f"⚠️ 疑わしいキーワード検出: {', '.join(found_keywords[:3])}")

    # URLチェック

    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)

    if urls:

        results["details"].append(f"検出されたURL数: {len(urls)}")

        dangerous_urls = []

        for url in urls[:5]:

            url_result = analyze_url_local(url)

            if url_result["risk_level"] == "危険":

                results["risk_level"] = "危険"

                results["risk_score"] = 90

                dangerous_urls.append(url)

            elif url_result["risk_level"] == "注意" and results["risk_level"] != "危険":

                results["risk_level"] = "注意"

                results["risk_score"] = max(results["risk_score"], 60)

        if dangerous_urls:

            results["warnings"].append(f"🚨 危険なURL発見: {len(dangerous_urls)}件")

    # 緊急性チェック

    urgent_words = ["今すぐ", "直ちに", "24時間以内", "immediately", "urgent"]

    if any(word in content.lower() for word in urgent_words):

        results["warnings"].append("⚠️ 緊急性を煽る表現が含まれています")

        results["risk_score"] = min(results["risk_score"] + 20, 100)

    return results

# サイドバー

with st.sidebar:

    st.header("⚙️ 設定")

    if not GEMINI_AVAILABLE:

        st.warning("⚠️ pip install google-generativeai")

    api_key = st.text_input(

        "Gemini APIキー（オプション）",

        type="password",

        help="AI分析を使用する場合は入力してください: https://aistudio.google.com/app/apikey"

    )

    st.markdown("---")

    st.markdown("""

    ### 📝 機能

    - **URLチェック**: URL安全性分析

    - **メールチェック**: メール内容分析

    - **ローカル分析**: データベースベース

    - **AI分析**: Gemini活用（要APIキー）

    - **通報機能**: 怪しいサイト共有

    - **脅威情報**: 最新データベース

    ### ⚠️ 注意

    - APIキーは安全に管理

    - 個人情報は入力禁止

    - 最終判断は慎重に

    """)

# メインタブ

tab1, tab2, tab3, tab4 = st.tabs(["🔍 URLチェック", "📧 メールチェック", "📢 通報・共有", "⚠️ 脅威情報"])

# タブ1: URLチェック

with tab1:

    st.header("🔍 URL安全性チェック")

    col1, col2 = st.columns([2, 1])

    with col1:

        url_input = st.text_area(

            "チェックするURLを入力",

            placeholder="https://example.com",

            height=100

        )

        col_btn1, col_btn2 = st.columns(2)

        with col_btn1:

            local_check = st.button("🔍 ローカル分析", type="primary", use_container_width=True)

        with col_btn2:

            ai_check = st.button("🤖 AI分析", use_container_width=True)

    with col2:

        st.info("""

        **チェックポイント:**

        - スペルミスがないか

        - HTTPSかHTTPか

        - ドメインが本物か

        - 短縮URLでないか

        - 既知の詐欺サイトか

        """)

    # ローカル分析

    if local_check and url_input:

        with st.spinner("🔍 分析中..."):

            result = analyze_url_local(url_input)

            st.markdown("---")

            st.subheader("📊 分析結果")

            # リスクレベル表示

            if result['risk_level'] == '危険':

                st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>このURLは危険です！アクセスしないでください。</p></div>', unsafe_allow_html=True)

            elif result['risk_level'] == '注意':

                st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>注意が必要です。慎重に確認してください。</p></div>', unsafe_allow_html=True)

            else:

                st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>このURLは比較的安全です。</p></div>', unsafe_allow_html=True)

            st.progress(result['risk_score'] / 100)

            col_a, col_b = st.columns(2)

            with col_a:

                st.subheader("⚠️ 警告")

                if result['warnings']:

                    for warning in result['warnings']:

                        st.warning(warning)

                else:

                    st.success("特に問題は検出されませんでした")

            with col_b:

                st.subheader("📋 詳細情報")

                for detail in result['details']:

                    st.text(detail)

    # AI分析

    if ai_check and url_input:

        if not api_key:

            st.error("❌ AI分析にはGemini APIキーが必要です（サイドバーで設定）")

        else:

            with st.spinner("🤖 AIが分析中..."):

                try:

                    genai.configure(api_key=api_key)

                    model = genai.GenerativeModel('gemini-1.5-flash')

                    prompt = f"""以下のURLがフィッシング詐欺サイトである可能性を分析してください。

URL: {url_input}

以下の形式でJSON形式で回答してください：

{{

  "risk_level": "high/medium/low",

  "risk_score": 0-100の数値,

  "is_suspicious": true/false,

  "indicators": ["疑わしい点のリスト"],

  "recommendation": "ユーザーへの推奨アクション",

  "summary": "分析結果の簡潔な要約"

}}"""

                    response = model.generate_content(

                        prompt,

                        generation_config=genai.types.GenerationConfig(

                            temperature=0.2,

                            max_output_tokens=1000,

                        )

                    )

                    json_match = re.search(r'\{[\s\S]*\}', response.text)

                    if json_match:

                        result = json.loads(json_match.group())

                        st.markdown("---")

                        st.subheader("📊 AI分析結果")

                        if result['risk_level'] == 'high':

                            st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)

                        elif result['risk_level'] == 'medium':

                            st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)

                        else:

                            st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)

                        st.progress(result['risk_score'] / 100)

                        col_a, col_b = st.columns(2)

                        with col_a:

                            st.subheader("🔍 検出された疑わしい点")

                            for i, indicator in enumerate(result['indicators'], 1):

                                st.markdown(f"{i}. {indicator}")

                        with col_b:

                            st.subheader("💡 推奨アクション")

                            st.info(result['recommendation'])

                    else:

                        st.error("❌ 分析結果の解析に失敗しました")

                except Exception as e:

                    st.error(f"❌ エラーが発生しました: {str(e)}")

# タブ2: メールチェック

with tab2:

    st.header("📧 メール内容チェック")

    col1, col2 = st.columns([2, 1])

    with col1:

        email_input = st.text_area(

            "メール本文を入力",

            placeholder="メールの内容を貼り付けてください",

            height=300

        )

        col_btn1, col_btn2 = st.columns(2)

        with col_btn1:

            email_local = st.button("🔍 ローカル分析（メール）", type="primary", use_container_width=True)

        with col_btn2:

            email_ai = st.button("🤖 AI分析（メール）", use_container_width=True)

    with col2:

        st.info("""

        **チェックポイント:**

        - 緊急性を煽っていないか

        - 個人情報を求めていないか

        - 不自然な日本語はないか

        - リンク先が正規サイトか

        - 疑わしいキーワードがないか

        """)

    # ローカル分析

    if email_local and email_input:

        with st.spinner("🔍 分析中..."):

            result = analyze_email_local(email_input)

            st.markdown("---")

            st.subheader("📊 分析結果")

            if result['risk_level'] == '危険':

                st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>このメールは詐欺の可能性が高いです！</p></div>', unsafe_allow_html=True)

            elif result['risk_level'] == '注意':

                st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>注意が必要です。慎重に確認してください。</p></div>', unsafe_allow_html=True)

            else:

                st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>このメールは比較的安全です。</p></div>', unsafe_allow_html=True)

            st.progress(result['risk_score'] / 100)

            col_a, col_b = st.columns(2)

            with col_a:

                st.subheader("⚠️ 警告")

                if result['warnings']:

                    for warning in result['warnings']:

                        st.warning(warning)

                else:

                    st.success("特に問題は検出されませんでした")

            with col_b:

                st.subheader("📋 詳細情報")

                for detail in result['details']:

                    st.text(detail)

    # AI分析

    if email_ai and email_input:

        if not api_key:

            st.error("❌ AI分析にはGemini APIキーが必要です")

        else:

            with st.spinner("🤖 AIが分析中..."):

                try:

                    genai.configure(api_key=api_key)

                    model = genai.GenerativeModel('gemini-1.5-flash')

                    prompt = f"""以下のメール内容がフィッシング詐欺である可能性を分析してください。

メール内容:

{email_input}

以下の形式でJSON形式で回答してください：

{{

  "risk_level": "high/medium/low",

  "risk_score": 0-100の数値,

  "is_suspicious": true/false,

  "indicators": ["疑わしい点のリスト"],

  "recommendation": "ユーザーへの推奨アクション",

  "summary": "分析結果の簡潔な要約"

}}"""

                    response = model.generate_content(

                        prompt,

                        generation_config=genai.types.GenerationConfig(

                            temperature=0.2,

                            max_output_tokens=1000,

                        )

                    )

                    json_match = re.search(r'\{[\s\S]*\}', response.text)

                    if json_match:

                        result = json.loads(json_match.group())

                        st.markdown("---")

                        st.subheader("📊 AI分析結果")

                        if result['risk_level'] == 'high':

                            st.markdown(f'<div class="risk-high"><h3>🚨 高リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)

                        elif result['risk_level'] == 'medium':

                            st.markdown(f'<div class="risk-medium"><h3>⚠️ 中リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)

                        else:

                            st.markdown(f'<div class="risk-low"><h3>✅ 低リスク ({result["risk_score"]}/100)</h3><p>{result["summary"]}</p></div>', unsafe_allow_html=True)

                        st.progress(result['risk_score'] / 100)

                        col_a, col_b = st.columns(2)

                        with col_a:

                            st.subheader("🔍 検出された疑わしい点")

                            for i, indicator in enumerate(result['indicators'], 1):

                                st.markdown(f"{i}. {indicator}")

                        with col_b:

                            st.subheader("💡 推奨アクション")

                            st.info(result['recommendation'])

                except Exception as e:

                    st.error(f"❌ エラーが発生しました: {str(e)}")

# タブ3: 通報・共有

with tab3:

    st.header("📢 怪しいサイト・メールを通報")

    with st.form("report_form"):

        report_url = st.text_input("URL", placeholder="https://suspicious-site.com")

        report_detail = st.text_area("詳細情報", placeholder="どのような詐欺の疑いがあるか説明してください", height=150)

        submitted = st.form_submit_button("📢 通報する", type="primary")

        if submitted:

            if report_url:

                report = {

                    "url": report_url,

                    "detail": report_detail,

                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                }

                st.session_state.reported_sites.append(report)

                st.success("✅ 通報ありがとうございます！情報はデータベースに追加されました。")

            else:

                st.error("❌ URLを入力してください")

    st.markdown("---")

    st.subheader("📋 最近の通報情報")

    if st.session_state.reported_sites:

        for i, report in enumerate(reversed(st.session_state.reported_sites[-10:]), 1):

            with st.expander(f"🚨 通報 #{len(st.session_state.reported_sites) - i + 1} - {report['url'][:50]}..."):

                st.text(f"日時: {report['timestamp']}")

                st.text(f"URL: {report['url']}")

                st.text(f"詳細: {report['detail']}")

    else:

        st.info("まだ通報はありません")

# タブ4: 脅威情報

with tab4:

    st.header("⚠️ 脅威情報データベース")

    col1, col2 = st.columns([3, 1])

    with col1:

        st.text(f"最終更新: {st.session_state.last_update}")

    with col2:

        if st.button("🔄 更新", use_container_width=True):

            # 通報されたサイトをデータベースに追加

            for report in st.session_state.reported_sites:

                domain = urlparse(report['url']).netloc

                if domain and domain not in st.session_state.threat_database["dangerous_domains"]:

                    st.session_state.threat_database["dangerous_domains"].append(domain)

            st.session_state.last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            st.success("✅ データベースを更新しました！")

            time.sleep(1)

            st.rerun()

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:

        st.subheader("🚫 危険なドメイン")

        for i, domain in enumerate(st.session_state.threat_database["dangerous_domains"], 1):

            st.markdown(f'<div class="threat-item">{i}. {domain}</div>', unsafe_allow_html=True)

    with col2:

        st.subheader("🔍 疑わしいキーワード")

        for i, keyword in enumerate(st.session_state.threat_database["suspicious_keywords"], 1):

            st.markdown(f'<div class="threat-item">{i}. {keyword}</div>', unsafe_allow_html=True)

# フッター

st.markdown("---")

st.markdown("""
<div style="text-align: center; color: #666; padding: 2rem;">
<p>⚠️ このツールは補助的なものです。最終的な判断は慎重に行ってください。</p>
<p>💡 ローカル分析は無料、AI分析にはGemini APIキーが必要です</p>
<p>Powered by Google Gemini AI & Local Threat Database</p>
</div>

""", unsafe_allow_html=True)
 
 