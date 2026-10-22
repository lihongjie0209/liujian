function onRequest(request) {
  request.display = preview(request);
  return request;
}

function onResponse(response) {
  response.display = preview(response);
  return response;
}

function preview(message) {
  var type = message.headers["Content-Type"] || [];
  if (!type.length || type[0].indexOf("json") < 0) return "";
  try {
    var body = message.body;
    var encoding = message.headers["Content-Encoding"] || [];
    if (encoding.length && encoding[0].toLowerCase() === "gzip") {
      body = ca.gzip.decompress(body);
    }
    return ca.json.pretty(body);
  } catch (error) {
    console.warn("JSON formatting failed:", error.message);
    return "";
  }
}
