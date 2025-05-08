const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    scanPC: () => ipcRenderer.invoke('scan-pc')
});
