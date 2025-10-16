import asyncio
import re
import os
import aiohttp
import aiofiles
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# ===== CONFIG =====
BOT_TOKEN = "8008678561:AAH80tlSuc-tqEYb12eXMfUGfeo7Wz8qUEU"
API_BASE = "http://127.0.0.1:5000/api"  # Local API
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2GB
CONCURRENT_DOWNLOADS = 10
semaphore = asyncio.Semaphore(CONCURRENT_DOWNLOADS)
# ==================

# ===== Commands =====
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = (
        "👋 *Terabox Downloader Bot*\n\n"
        "📥 Send me Terabox link(s) and I'll download them.\n"
        "⚠️ Max file size: 2GB\n\n"
        "Available commands:\n"
        "/start - Show this message"
    )
    await update.message.reply_text(msg, parse_mode="Markdown")

# ===== Download Function =====
async def download_and_send(update: Update, file_info: dict, failed_links: list, session: aiohttp.ClientSession):
    async with semaphore:
        try:
            download_url = file_info["Direct Download Link"]
            size_bytes = file_info.get("sizebytes", 0)
            if size_bytes > MAX_FILE_SIZE:
                failed_links.append(file_info.get("link", "Unknown"))
                return

            filename = file_info.get("Title", "file.mp4")
            caption = f"🎬 *{filename}*\n📦 Size: {file_info['Size']}"

            file_path = f"/tmp/{filename}"
            async with session.get(download_url) as r:
                r.raise_for_status()
                async with aiofiles.open(file_path, "wb") as f:
                    async for chunk in r.content.iter_chunked(8192):
                        await f.write(chunk)

            await update.message.reply_video(
                video=open(file_path, "rb"),
                caption=caption,
                parse_mode="Markdown"
            )
            os.remove(file_path)
        except Exception as e:
            print("Error downloading file:", e)
            failed_links.append(file_info.get("link", "Unknown"))

# ===== Message Handler =====
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or getattr(update.message, "caption", None)
    if not text:
        return

    clean_text = re.sub(r"[^\x20-\x7E]+", " ", text)
    clean_text = re.sub(r"\s+", " ", clean_text)
    links = list(dict.fromkeys(
        re.findall(r"https?://(?:www\.)?(?:terabox|1024terabox|teraboxshare)\.com/s/[A-Za-z0-9_-]+", clean_text)
    ))
    if not links:
        return

    msg = await update.message.reply_text(f"🔍 Found {len(links)} link(s). Starting downloads...")
    failed_links = []

    async with aiohttp.ClientSession() as session:
        for link in links:
            try:
                async with session.get(f"{API_BASE}?url={link}") as resp:
                    data = await resp.json()

                if data.get("status") != "success" or not data.get("Extracted Info"):
                    failed_links.append(link)
                    continue

                tasks = [
                    asyncio.create_task(download_and_send(update, file_info, failed_links, session))
                    for file_info in data["Extracted Info"]
                ]
                await asyncio.gather(*tasks)

            except Exception as e:
                print("Error calling API:", e)
                failed_links.append(link)

    if failed_links:
        await update.message.reply_text(
            "❌ Failed to download the following link(s):\n" + "\n".join(failed_links)
        )

    await msg.delete()

# ===== Bot Launcher =====
def run_bot():
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🚀 Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    run_bot()
