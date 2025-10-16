# TeraBox Downloader Bot

A Telegram bot that downloads files from TeraBox links and sends them directly to users.

## Features

- 📥 Download files from TeraBox links
- 🤖 Telegram bot interface
- 🐳 Docker support for easy deployment
- ☁️ Ready for Coolify deployment

## Components

- **Node.js API Server** (`server.js`): Handles TeraBox API interactions
- **Python Telegram Bot** (`bot.py`): Manages user interactions
- **TeraBox API Library** (`api.js`): Core API functionality

## Environment Variables

Create a `.env` file with:

```
BOT_TOKEN=your_telegram_bot_token_here
PORT=5000
```

## Local Development

### Using Docker

```bash
docker build -t terabox-bot .
docker run -p 5000:5000 -e BOT_TOKEN=your_token terabox-bot
```

### Using Docker Compose

```bash
docker-compose up -d
```

## Coolify Deployment

1. Push your code to a Git repository
2. In Coolify, create a new application
3. Select your repository
4. Set environment variable: `BOT_TOKEN`
5. Deploy!

Coolify will automatically detect the Dockerfile and build your application.

## API Endpoints

### GET /api

Extract TeraBox file information.

**Parameters:**
- `url` (required): TeraBox share link

**Example:**
```
http://localhost:5000/api?url=https://terabox.com/s/1abc123
```

## Bot Commands

- `/start` - Show welcome message and instructions

## Usage

1. Start the bot on Telegram
2. Send a TeraBox link
3. Bot will extract and download the file
4. File will be sent to you on Telegram

## Limitations

- Max file size: 2GB (Telegram limitation)
- Concurrent downloads: 10

## License

MIT
