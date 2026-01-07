
<img width="1135" height="387" alt="AIEL Trace" src="https://github.com/user-attachments/assets/9763d537-0a75-4467-940a-2a929da87921" />

<p align="center">
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python">
  </a>
  <a href="https://github.com/astral-sh/ruff">
    <img src="https://img.shields.io/badge/lint-ruff-46a2f1" alt="Ruff">
  </a>
  <a href="https://github.com/Sh1ragami/AIEL-Trace/issues">
    <img src="https://img.shields.io/github/issues/Sh1ragami/AIEL-Trace" alt="Issues">
  </a>
  <a href="https://github.com/Sh1ragami/AIEL-Trace/commits/main">
    <img src="https://img.shields.io/github/last-commit/Sh1ragami/AIEL-Trace" alt="Last Commit">
  </a>
  <a href="https://github.com/Sh1ragami/AIEL-Trace">
    <img src="https://img.shields.io/github/stars/Sh1ragami/AIEL-Trace?style=social" alt="Stars">
  </a>
</p>

<br/>

## 概要
- PySide6（Qt）製のローカルデスクトップGUI脆弱性スキャナです。MBSD2025のコンテスト用に開発しました。

<br/>

## 主な特徴（Features）
- スキャンモード: セーフ / 通常 / 攻撃（侵襲度を段階制御）
- パス列挙: 既知パスの辞書照合＋同一オリジン内リンクのクロール
- 受動チェック例: セキュリティヘッダ不足、ディレクトリリスティング、情報漏えい、CORS/HSTS/Cookie属性、デバッグ残存 など
- 能動チェック例: HTTPS適用漏れ、CORS反射、パラメータ改ざん、テンプレートインジェクション兆候、SSRFの可能性、HTTPメソッド/XST など
- 攻撃モード例: CRLF/ヘッダインジェクション、OSコマンドインジェクション（時間差/エラー）、ディレクトリトラバーサル、ファイルアップロード など（オプトイン）
- XSS系: DOMシンク観測、DOM反射/格納型の簡易検知（自動フォーム投入）
- 認証支援: 簡易ログイン試行、AIへ認証情報を共有（任意）
- ベースライン比較: JSONを取り込み、新規/未解決/修正済みをUI表示
- レポート出力: Markdown/HTML/PDF/DOCX（AIEL）/JSON

<br/>

## スクリーンショット

<table>
  <tr>
    <td align="center">
      <h4>パス列挙</h4>
      <img src="https://github.com/user-attachments/assets/d4499af3-7267-4a46-9139-47202d2b84be" width="720" alt="Dashboard">
    </td>
    <td align="center">
      <h4>画面プレビュー</h4>
      <img src="https://github.com/user-attachments/assets/60208f6c-894d-433e-8042-29ce7d3ce0ca" width="720" alt="Target Setup">
    </td>
  </tr>
  <tr>
    <td align="center">
      <h4>ソースコードプレビュー</h4>
      <img src="https://github.com/user-attachments/assets/bf2f11d0-a16b-417c-b9df-338d8b07dd49" width="720" alt="Endpoint Enumeration">
    </td>
    <td align="center">
      <h4>スキャンオプション設定</h4>
      <img src="https://github.com/user-attachments/assets/54892715-2080-4da5-bf0d-297138aaa6af" width="720" alt="Scan Results">
    </td>
  </tr>
  <tr>
    <td align="center">
      <h4>スキャン結果一覧</h4>
      <img src="https://github.com/user-attachments/assets/810bd607-7ab3-4421-84ea-ebf430d65b7e" width="720" alt="AI Agent Browser">
    </td>
    <td align="center">
      <h4>スキャン結果詳細</h4>
      <img src="https://github.com/user-attachments/assets/2a2279f9-921f-4831-9fb7-1f8782e6ed2b" width="720" alt="Report & Export">
    </td>
  </tr>
</table>

<br/>

## インストール（Native）
前提:
- Python 3.10+
- Ollama（デフォルト: http://localhost:11434）。モデル例: `llama3.1:latest`

手順:
- 仮想環境を推奨（例: `python -m venv .venv && source .venv/bin/activate`）
- 依存インストール: `pip install -e .`（開発向け: `pip install -e .[dev]`）
- モデル準備（例）: `ollama pull llama3.1`
- 実行:
  - GUIを起動: `mbsd-tool` または `python -m mbsd_tool`

## インストール（Docker）
- Linux + X11 共有例:
  1) `docker compose up --build`
  2) X11許可: `xhost +local:`（終了後は `xhost -local:` で戻す）
  3) ホストのXサーバにウィンドウが表示されます

注意: macOS/WindowsでX11表示にはXQuartz（macOS）やXサーバ（Windows）が必要です。将来的にnoVNC経由のブラウザ表示も提供予定です。

<br/>

## 使い方
1) ターゲットURLを入力（例: `http://localhost/`）
2) モードを選択（セーフ/通常/攻撃）
3) 「パス列挙」→ 表示されたエンドポイントを確認し「エンドポイントをスキャン」
4) 右側のエージェントブラウザでAI操作やDOM観測結果を確認
5) 結果/レポートタブからエクスポート（Markdown/HTML/PDF/DOCX/JSON）

ベースライン比較（差分トラッキング）
- スキャン後に「比較用ファイル保存(JSON)」でベースラインを保存
- 次回スキャン時に「前回ファイル読込」で読み込むと、詳細表に「状態（新規/未解決）」を表示。別ダイアログで「修正済み」を確認
- 既存のScanResult（JSON）も自動変換して比較可能

環境変数・設定
- `OLLAMA_URL`（既定: `http://localhost:11434`）
- `OLLAMA_MODEL`（既定: `llama3.1:latest`）

CLI
- エントリポイント: `mbsd-tool`
- モジュールから: `python -m mbsd_tool`

<br/>

## 安全な利用について
- 本ツールは、利用者が権限を有するシステムに対してのみ使用してください。
- 攻撃モードは侵襲的な検査を含みます。業務・法令・契約・社内規程に従い、関係者の合意を得た上で実施してください。
- 実運用環境での試験は推奨しません。検証環境での利用をご検討ください。

<br/>

## ディレクトリ構成
- `mbsd_tool/`
  - `gui/` — Qt GUI（タブ、Webパネル、テーマ）
  - `core/` — 列挙/スキャナ/AIエージェント/レポート/モデル
  - `config/` — 設定（OllamaのURL/モデル）
  - `resources/` — アイコン/QSS等
- `docker/` — Dockerfileや補助スクリプト

<br/>

## ライセンス
- MIT LICENCE
