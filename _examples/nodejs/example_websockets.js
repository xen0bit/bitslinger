var { WebSocket } = require('ws');

const ws = new WebSocket('ws://127.0.0.1:9393/bitslinger');

function unpackBitSlinger(message) {
  var segments = message.split('\n');
  if (segments.length == 2) {
    var packetUuid = segments[0];
    var packetPayload = Buffer.from(segments[1], 'hex')
    return [packetUuid, packetPayload]
  }
}

function packBitSlinger(packetUuid, packetPayload) {
  return packetUuid + '\n' + Buffer.toString('hex')
}

function modifyPayload(packetPayload) {
  return Buffer.from(packetPayload.toString().replace('world', 'remy!'), 'utf8');
}

ws.on('open', function open() {
  console.log('Connected!')
});


ws.on('message', function data(message) {
    // console.log(message.toString())
    // var unpacked = unpackBitSlinger(message.toString())
    // var packetUuid = unpacked[0];
    // var packetPayload = unpacked[1];
    // console.log(packetUuid, packetPayload);
    // var newPacketPayload = modifyPayload(packetPayload)
    // console.log(newPacketPayload);
    // var newMessage = packBitSlinger(packetUuid, newPacketPayload)
    // console.log(newMessage.toString())
    // ws.send(newMessage);
    ws.send(message);
});

process.on('SIGINT', function () {
  ws.close();
  process.exit();
});