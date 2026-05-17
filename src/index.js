export default {
  async fetch(request) {

    if (request.url.endsWith("/api/test")) {
      return Response.json({
        message: "Backend OK"
      });
    }

    return new Response(`
      <!DOCTYPE html>
      <html>
      <body>
        <h1>Frontend OK</h1>

        <script>
          fetch('/api/test')
            .then(r => r.json())
            .then(data => {
              document.body.innerHTML +=
                '<p>' + data.message + '</p>';
            });
        </script>
      </body>
      </html>
    `, {
      headers: {
        "content-type": "text/html"
      }
    });
  }
}
