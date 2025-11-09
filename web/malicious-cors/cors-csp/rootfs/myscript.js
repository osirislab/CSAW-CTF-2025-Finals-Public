const puppeteer = require('puppeteer');

if (process.argv.length < 3) {
    console.log('Usage: node myscript.js [some URL]');
    process.exit(1);
}

const url = process.argv[2];

(async () => {
    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--ignore-certificate-errors',
		        '--disable-web-security',
		        '--user-data-dir=/tmp/chrome-user-data'
            ],
            executablePath: '/usr/bin/chromium'
        });
        
        const page = await browser.newPage();
		await page.setExtraHTTPHeaders({
            'ngrok-skip-browser-warning': 'true'
        });
        
        await page.goto(url, {
            waitUntil: 'networkidle2',
            timeout: 10000
        });

        await new Promise(resolve => setTimeout(resolve, 5000));

    } catch (error) {
        console.log('Error: ' + error.message);
    } finally {
        if (browser) {
            await browser.close();
        }
    }
})();
