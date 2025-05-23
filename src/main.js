const { app, BrowserWindow, ipcMain } = require('electron');
const si = require('systeminformation');

// Create scanner window
function createWindow() {
    const win = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js')
        }
    });

    win.loadFile('public/index.html');
}

// Handle PC scan requests
ipcMain.handle('scan-pc', async () => {
    return {
        cpu: await si.cpu(),
        gpu: await si.graphics(),
        memLayout: await si.memLayout()
    };
});

app.whenReady().then(createWindow);

import { ipcMain } from 'electron';

ipcMain.handle('2fa:generate-secret', async (event, userId) => {
  return await authService.generateSecret(userId);
});

ipcMain.handle('2fa:verify-code', async (event, { userId, token }) => {
  return await authService.verifyToken(userId, token);
});
