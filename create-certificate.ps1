# Always Encrypted 证书生成脚本
# 用于RBA项目的Always Encrypted实现

Write-Host "🔐 生成Always Encrypted证书..." -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

try {
    # 生成自签名证书
    $cert = New-SelfSignedCertificate `
        -Subject "CN=RBA_AlwaysEncrypted_Certificate" `
        -KeyExportPolicy Exportable `
        -KeySpec KeyExchange `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyUsage KeyEncipherment,DataEncipherment,KeyAgreement `
        -Type DocumentEncryptionCert

    Write-Host "✅ 证书生成成功!" -ForegroundColor Green
    Write-Host "📋 证书信息:" -ForegroundColor Yellow
    Write-Host "   主题: $($cert.Subject)" -ForegroundColor White
    Write-Host "   指纹: $($cert.Thumbprint)" -ForegroundColor White
    Write-Host "   有效期: $($cert.NotBefore) 到 $($cert.NotAfter)" -ForegroundColor White
    Write-Host "   存储位置: Cert:\CurrentUser\My\$($cert.Thumbprint)" -ForegroundColor White
    
    Write-Host ""
    Write-Host "🚀 下一步操作:" -ForegroundColor Green
    Write-Host "1. 证书已安装到当前用户证书存储" -ForegroundColor White
    Write-Host "2. 现在可以运行: npm run setup:basic-encryption" -ForegroundColor White
    Write-Host "3. 如果需要导出证书，请运行: npm run export:certificate" -ForegroundColor White
    
} catch {
    Write-Host "❌ 证书生成失败: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "请以管理员身份运行PowerShell" -ForegroundColor Yellow
} 