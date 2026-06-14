const WebSocket = require("ws")

const sendBtn = document.getElementById("sendButton")
const msgBox = document.getElementById("messageBox")
const chatArea = document.getElementById("chatArea")
const socket = null
const host = "ws://"

let messages = []

// funcs dealing with messages
function addMessage(msg) {
    if (messages.length > 100)
        messages.pop(0)
    messages.push(msg)
}
function updateChatArea() {
    chatArea.innerHTML = messages.map((msg) =>
        `<p>${msg}</p>`
    ).join('')
}

// funcs dealing with sockets
function connect() {
    try {
        socket = new WebSocket(host)
    } catch (error) {
        sendingError(error)
    }
}
async function sendMessage() {
    if (!socket) connect()
    let msg = msgBox.value;
    msg = msg.trim()

    try {
        if (msg.length <= 0)
            throw new Error("Empty string provided! Message must contain at least 1 character.")
        socket.send(msg)
    } catch (error) {
        sendingError(error)
    }
    addMessage(`[Me @ ${time}]: ${msg}`)
    updateChatArea()
}
function recvMessage(msgData) {
    let user = msgData.user.trim()
    let txt = msgData.text.trim()
    let time = msgData.timestamp
    addMessage(`[${user} @ ${time}]: ${msg}`)
    updateChatArea()
}

// funcs for error logs
function sendingError(error) {
    window.alert("An error occurred while sending your message. View logs for more info.")
    console.log(error)
}

// config
sendBtn.addEventListener("click", sendMessage)
connect()
socket.addEventListener("message", (event) => {
    const msgData = JSON.parse(event.data)
    recvMessage(msgData)
})