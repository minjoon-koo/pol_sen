var http = require('http');
var fs = require('fs');
var url = require('url');
var qs = require('querystring');
const { exec } = require('child_process');


function templateHTML(body){
    return `
    <!doctype html>
    <html>
    <head>
      <title>AWS IAM POLICY Control</title>
      <meta charset="utf-8">
    </head>
    <body>
    <form action="/pypol" method="post">
    <p><input type="text" name="RoleName" placeholder="RoleName"></p>
    <p>
      <textarea name="ARN" placeholder="arn,arn"></textarea>
    </p>
    <p>list <input type="checkbox" name="ListAcc" value="T"></p>
    <p>read <input type="checkbox" name="ReadAcc" value="T"></p>
    <p>write <input type="checkbox" name="WriteAcc" value="T"></p>
    <b>RoleDelete 선택 시 해당 정책 삭제</b>
    <p>RoleDelete <input type="checkbox" name="RoleDelete" value="T" onclick="only(this)"></p>
    <p>
      <input type="submit">
    </p>
  </form>
  </br>
    결과 값 </br> >
      ${body}
    </body>
    </html>
    `;
  }


var app = http.createServer(function(request,response){
    var _url = request.url;
    var queryData = url.parse(_url, true).query;
    var pathname = url.parse(_url, true).pathname;

    if(pathname === '/'){
        var template = templateHTML(``);
          response.writeHead(200);
          response.end(template);
    }
    
    else if(pathname === '/pypol'){
        var body = '';
        request.on('data', function(data){
            body = body + data;
        });
        request.on('end', function(){
            var post = qs.parse(body);
            var ARN = post.ARN;
            var ARNList = ARN.split(',');
            var JsonParam = {
                "ARN" : ARNList,
                "RoleName" : post.RoleName, 
                'ListAcc' : post.ListAcc,
                'ReadAcc' : post.ReadAcc,
                'WriteAcc' : post.WriteAcc,
                'RoleDelete' : post.RoleDelete,
                'stsAcc' : post.stsAcc
            };

            var tmp = JSON.stringify(JsonParam);
            cmd = "python3 ../backend/UpdatePolicy.py '"+ tmp +"'"
            exec(cmd, (err, stdout, stderr) => {
                var template = templateHTML(`${stderr}`);
                response.writeHead(200);
                response.end(template);
            });
            
        });
  
    }
 
});
app.listen(3000);