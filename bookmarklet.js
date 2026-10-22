(function(){
  var SAFE={"8.5":[8,5,12],"8.4":[8,4,27],"8.3":[8,3,36],"8.2":[8,2,35]};
  var PATHS=["","phpinfo.php","info.php"];
  function parseV(t){if(!t)return null;var m=String(t).match(/PHP(?:\s*Version)?\/?\s*(\d+)\.(\d+)(?:\.(\d+))?/i);if(!m)return null;return{v:[+m[1],+m[2],m[3]?+m[3]:null],raw:m[0]};}
  function classify(p){if(!p)return{level:"unknown"};var a=p.v[0],b=p.v[1],c=p.v[2],br=a+"."+b;if(a<8||(a===8&&b<=1))return{level:"eol",branch:br};if(SAFE[br]){if(c==null)return{level:"review",branch:br,need:SAFE[br][2]};return{level:(c>=SAFE[br][2])?"ok":"vulnerable",branch:br,need:SAFE[br][2]};}if(a>8||(a===8&&b>=6))return{level:"ok",branch:br,future:1};return{level:"unknown"};}
  var V={vulnerable:["#B3261E","Action needed","Running a PHP version that needs the emergency update"],eol:["#B34418","Action needed","Running an end-of-life PHP version"],review:["#8A5A12","Check with IT","Affected PHP branch, exact patch level not shown"],ok:["#2E6E4F","Looks patched","PHP version includes the fix"],unknown:["#3D5265","No version shown","This page did not reveal its PHP version"],error:["#253746","Could not check","Could not read this page's version information"]};

  function gather(){
    var origin=location.origin, out=[];
    // Evidence from the current DOM first (no request needed).
    var domText=(document.documentElement&&document.documentElement.innerText||"").slice(0,20000);
    out.push({path:"(this page, DOM)",ok:true,server:"",xpb:"",body:parseV(domText)?("PHP Version "+parseV(domText).v.join(".").replace(/\.null$/,"")+" (in page text)"):""});
    // Same-origin requests can read headers and body legitimately.
    var jobs=PATHS.map(function(p){
      var u=origin+"/"+p;
      return fetch(u,{method:"GET",redirect:"follow",credentials:"omit"}).then(function(r){
        return r.text().then(function(txt){
          var bp=parseV(txt);
          return {path:p?("/"+p):"/ (home)",ok:true,status:r.status,server:r.headers.get("Server")||"",xpb:r.headers.get("X-Powered-By")||"",body:bp?("PHP Version "+bp.v.join(".").replace(/\.null$/,"")+" (in page content)"):""};
        });
      }).catch(function(e){return {path:p?("/"+p):"/ (home)",ok:false,error:(e&&e.message)||"blocked"};});
    });
    return Promise.all(jobs).then(function(res){return out.concat(res);});
  }

  function best(items){
    for(var i=0;i<items.length;i++){var it=items[i];if(!it.ok)continue;var p=parseV(it.xpb)||parseV(it.server)||parseV(it.body);if(p)return p;}
    return null;
  }

  function set(el,styles){for(var k in styles)el.style[k]=styles[k];}
  function panel(items){
    var bp=best(items), vd=classify(bp), meta=V[vd.level]||V.unknown;
    var old=document.getElementById("__php2shell");if(old)old.remove();
    var box=document.createElement("div");box.id="__php2shell";
    set(box,{position:"fixed",top:"16px",right:"16px",zIndex:2147483647,width:"360px",maxWidth:"92vw",maxHeight:"88vh",overflow:"auto",background:"#fff",color:"#1A1A1A",borderRadius:"16px",boxShadow:"0 10px 40px rgba(0,0,0,.35)",font:'14px/1.5 Arial,Helvetica,sans-serif'});
    var head=document.createElement("div");
    set(head,{background:meta[0],color:"#fff",padding:"16px 18px",borderRadius:"16px 16px 0 0"});
    var tag=document.createElement("div");tag.textContent=meta[1].toUpperCase();set(tag,{fontWeight:"bold",fontSize:"11px",letterSpacing:".06em",opacity:".9"});
    var h=document.createElement("div");h.textContent=meta[2];set(h,{fontWeight:"bold",fontSize:"17px",marginTop:"6px"});
    var det=document.createElement("div");det.textContent=bp?("Detected PHP "+bp.v.join(".").replace(/\.null$/,"")+(vd.need!=null?("  |  safe from "+vd.branch+"."+vd.need):"")):"No PHP version found on this page.";set(det,{marginTop:"8px",fontSize:"13px",opacity:".95"});
    head.appendChild(tag);head.appendChild(h);head.appendChild(det);
    var body=document.createElement("div");set(body,{padding:"14px 18px"});
    var site=document.createElement("div");site.textContent="Site: "+location.origin;set(site,{fontWeight:"bold",color:"#0f172a",marginBottom:"8px",wordBreak:"break-all"});
    body.appendChild(site);
    items.forEach(function(e){
      var row=document.createElement("div");set(row,{borderTop:"1px solid #E3DED8",padding:"8px 0",fontSize:"12px"});
      var p=document.createElement("div");p.textContent=e.path+(e.ok&&e.status?("  ["+e.status+"]"):"");set(p,{fontWeight:"bold",color:"#253746"});
      row.appendChild(p);
      var lines=[];if(e.server)lines.push("Server: "+e.server);if(e.xpb)lines.push("X-Powered-By: "+e.xpb);if(e.body)lines.push(e.body);if(!e.ok)lines.push(e.error||"no response");
      var d=document.createElement("div");d.textContent=lines.length?lines.join("  |  "):"no version information";set(d,{color:"#3D5265",wordBreak:"break-all",fontFamily:"monospace"});
      row.appendChild(d);body.appendChild(row);
    });
    var note=document.createElement("div");note.textContent="Advertised version only, not a full scan. A hidden version is not a guarantee of safety; Linux packages may be patched while keeping an old number. Confirm with IT. CVE-2026-109618 / CVE-2026-109619.";set(note,{marginTop:"10px",fontSize:"11px",color:"#3D5265"});
    body.appendChild(note);
    var x=document.createElement("button");x.textContent="Close";set(x,{marginTop:"12px",width:"100%",padding:"10px",border:"2px solid #0f172a",background:"#fff",color:"#0f172a",borderRadius:"10px",fontWeight:"bold",cursor:"pointer"});x.onclick=function(){box.remove();};
    body.appendChild(x);
    box.appendChild(head);box.appendChild(body);document.body.appendChild(box);
  }
  try{gather().then(panel).catch(function(){panel([{path:"(this page)",ok:false,error:"blocked by this site's security policy"}]);});}
  catch(e){alert("PHP2Shell checker could not run on this page: "+e.message);}
})();
