const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    scanPC: () => ipcRenderer.invoke('scan-pc')
});
contextBridge.exposeInMainWorld('api', {
  twoFactorAuth: {
    generateSecret: (userId) => ipcRenderer.invoke('2fa:generate-secret', userId),
    verifyCode: (data) => ipcRenderer.invoke('2fa:verify-code', data)
  }
});
