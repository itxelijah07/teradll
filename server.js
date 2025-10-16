import express from 'express';
import TeraBoxApp from './api.js';

const app = express();
const PORT = process.env.PORT || 5000;

app.use(express.json());

app.get('/api', async (req, res) => {
    try {
        const { url } = req.query;

        if (!url) {
            return res.status(400).json({
                status: 'error',
                message: 'URL parameter is required'
            });
        }

        // Extract shorturl from the TeraBox link
        const match = url.match(/\/s\/([A-Za-z0-9_-]+)/);
        if (!match) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid TeraBox URL'
            });
        }

        const shortUrl = match[1];

        // Initialize TeraBoxApp
        const tbApp = new TeraBoxApp('');
        await tbApp.updateAppData();

        // Get share info
        const shareInfo = await tbApp.shortUrlInfo(shortUrl);

        if (shareInfo.errno !== 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Failed to get share info',
                errno: shareInfo.errno
            });
        }

        // Get file list
        const fileList = await tbApp.shortUrlList(shortUrl);

        if (fileList.errno !== 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Failed to get file list',
                errno: fileList.errno
            });
        }

        // Extract file information
        const extractedInfo = fileList.list.map(file => ({
            'Title': file.server_filename,
            'Size': formatFileSize(file.size),
            'sizebytes': file.size,
            'Direct Download Link': file.dlink || '',
            'link': url,
            'fs_id': file.fs_id
        }));

        res.json({
            status: 'success',
            'Extracted Info': extractedInfo
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
});

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

app.listen(PORT, () => {
    console.log(`API Server running on port ${PORT}`);
});
