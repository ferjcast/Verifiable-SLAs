FROM node:22
WORKDIR /app
RUN npm install @phala/dstack-sdk  merkletreejs ethers axios
COPY app.js .
EXPOSE 3003
CMD ["node", "app.js"]
