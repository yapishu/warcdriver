/-  *warc
/+  default-agent, dbug, server
|%
+$  versioned-state  $%([%0 =state-0])
+$  state-0
  $:  bookmarks=(map bookmark-id bookmark)
      fetches=(map @ta fetch-batch)
  ==
+$  fetch-batch
  $:  total=@ud
      done=(map @ud fetch-result)
      urls=(list @t)
  ==
+$  fetch-result
  $%  [%ok status=@ud headers=(list [@t @t]) body=@t]
      [%fail msg=@t]
  ==
+$  card  card:agent:gall
--
::
%-  agent:dbug
=|  state-0
=*  state  -
^-  agent:gall
=<
|_  =bowl:gall
+*  this  .
    def   ~(. (default-agent this %|) bowl)
::
++  on-init
  ^-  (quip card _this)
  :_  this
  :~  [%pass /eyre/connect %arvo %e %connect [~ /apps/warc] %warc]
  ==
::
++  on-save  !>([%0 state])
::
++  on-load
  |=  old-state=vase
  ^-  (quip card _this)
  =/  old  (mule |.(!<(versioned-state old-state)))
  ?:  ?=(%| -.old)
    `this
  ?-  -.p.old
      %0
    `this(state state-0.p.old(fetches ~))
  ==
::
++  on-poke
  |=  [=mark =vase]
  ^-  (quip card _this)
  |^
  ?+  mark  (on-poke:def mark vase)
  ::
      %json
    ?>  =(src.bowl our.bowl)
    =/  jon  !<(json vase)
    =/  act  (parse-action jon)
    (handle-action act)
  ::
      %handle-http-request
    =+  !<([eyre-id=@ta req=inbound-request:eyre] vase)
    (handle-http eyre-id req)
  ==
  ::
  ++  handle-action
    |=  act=action
    ^-  (quip card _this)
    ?-  -.act
        %save
      =/  bm=bookmark  [url.act title.act (silt tags.act) s3-path.act now.bowl]
      =.  bookmarks  (~(put by bookmarks) id.act bm)
      :_  this
      :~  [%give %fact ~[/updates] %json !>((bookmark-to-json id.act bm))]  ==
    ::
        %delete
      =.  bookmarks  (~(del by bookmarks) id.act)
      :_  this
      :~  [%give %fact ~[/updates] %json !>((del-to-json id.act))]  ==
    ::
        %add-tag
      =/  bm  (~(got by bookmarks) id.act)
      =.  tags.bm  (~(put in tags.bm) tag.act)
      =.  bookmarks  (~(put by bookmarks) id.act bm)
      :_  this
      :~  [%give %fact ~[/updates] %json !>((bookmark-to-json id.act bm))]  ==
    ::
        %remove-tag
      =/  bm  (~(got by bookmarks) id.act)
      =.  tags.bm  (~(del in tags.bm) tag.act)
      =.  bookmarks  (~(put by bookmarks) id.act bm)
      :_  this
      :~  [%give %fact ~[/updates] %json !>((bookmark-to-json id.act bm))]  ==
    ==
  ::
  ++  handle-http
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  url=@t  url.request.req
    =/  met=method:http  method.request.req
    ?:  =(%'GET' met)
      :_  this
      ?+  url
        (give-http eyre-id 404 ~[['content-type' 'text/plain']] (some (as-octs:mimes:html 'not found')))
      ::
          %'/apps/warc'
        (give-http eyre-id 301 ~[['location' '/apps/warc/']] ~)
      ::
          %'/apps/warc/'
        =/  fil  .^(@t %cx /(scot %p our.bowl)/warc/(scot %da now.bowl)/site/index/html)
        (give-http eyre-id 200 ~[['content-type' 'text/html']] (some (as-octs:mimes:html fil)))
      ::
          %'/apps/warc/index.html'
        =/  fil  .^(@t %cx /(scot %p our.bowl)/warc/(scot %da now.bowl)/site/index/html)
        (give-http eyre-id 200 ~[['content-type' 'text/html']] (some (as-octs:mimes:html fil)))
      ::
          %'/apps/warc/warc.js'
        =/  fil  .^(@t %cx /(scot %p our.bowl)/warc/(scot %da now.bowl)/site/warc/js)
        (give-http eyre-id 200 ~[['content-type' 'application/javascript']] (some (as-octs:mimes:html fil)))
      ::
          %'/apps/warc/style.css'
        =/  fil  .^(@t %cx /(scot %p our.bowl)/warc/(scot %da now.bowl)/site/style/css)
        (give-http eyre-id 200 ~[['content-type' 'text/css']] (some (as-octs:mimes:html fil)))
      ::
          %'/apps/warc/api/s3-config'
        =/  resp=@t  (en:json:html (scry-s3-config bowl))
        (give-http eyre-id 200 ~[['content-type' 'application/json']] (some (as-octs:mimes:html resp)))
      ::
          %'/apps/warc/api/bookmarks'
        =/  resp=@t  (en:json:html (all-bookmarks-json ~(tap by bookmarks)))
        (give-http eyre-id 200 ~[['content-type' 'application/json']] (some (as-octs:mimes:html resp)))
      ==
    ?:  &(=(%'POST' met) =(url '/apps/warc/api/fetch'))
      (handle-fetch eyre-id req)
    ?:  &(=(%'POST' met) =(url '/apps/warc/api/action'))
      (handle-api-action eyre-id req)
    :_  this
    (give-http eyre-id 405 ~[['content-type' 'text/plain']] (some (as-octs:mimes:html 'method not allowed')))
  ::
  ++  handle-api-action
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  body-cord=@t
      ?~  body.request.req  ''
      `@t`q.u.body.request.req
    =/  jon=(unit json)  (de:json:html body-cord)
    ?~  jon
      :_  this
      (give-http eyre-id 400 ~[['content-type' 'text/plain']] (some (as-octs:mimes:html 'bad json')))
    =/  act  (parse-action u.jon)
    =/  [cards=(list card) new=_this]  (handle-action act)
    :_  new
    (give-http eyre-id 200 ~[['content-type' 'application/json']] (some (as-octs:mimes:html '{"ok":true}')))
  ::
  ++  handle-fetch
    |=  [eyre-id=@ta req=inbound-request:eyre]
    ^-  (quip card _this)
    =/  body-cord=@t
      ?~  body.request.req  ''
      `@t`q.u.body.request.req
    =/  jon=(unit json)  (de:json:html body-cord)
    ?~  jon
      :_  this
      (give-http eyre-id 400 ~[['content-type' 'text/plain']] (some (as-octs:mimes:html 'bad json')))
    =/  urls=(list @t)  ((ar:dejs:format so:dejs:format) u.jon)
    ?:  =(~ urls)
      :_  this
      (give-http eyre-id 400 ~[['content-type' 'text/plain']] (some (as-octs:mimes:html 'no urls')))
    =/  batch=fetch-batch  [(lent urls) ~ urls]
    =.  fetches  (~(put by fetches) eyre-id batch)
    =/  cards=(list card)
      =|  idx=@ud
      |-
      ?~  urls  ~
      :_  $(urls t.urls, idx +(idx))
      :*  %pass
          /fetch/[eyre-id]/(scot %ud idx)
          %arvo  %i
          %request
          [%'GET' i.urls ~ ~]
          *outbound-config:iris
      ==
    [cards this]
  --
::
++  on-watch
  |=  =path
  ^-  (quip card _this)
  ?+  path  (on-watch:def path)
      [%http-response *]  `this
      [%updates ~]
    :_  this
    :~  [%give %fact ~ %json !>((all-bookmarks-json ~(tap by bookmarks)))]
    ==
  ==
::
++  on-leave  on-leave:def
::
++  on-peek
  |=  =path
  ^-  (unit (unit cage))
  ?+  path  (on-peek:def path)
      [%x %bookmarks ~]
    ``json+!>((all-bookmarks-json ~(tap by bookmarks)))
      [%x %s3 ~]
    ``json+!>((scry-s3-config bowl))
  ==
::
++  on-agent  on-agent:def
::
++  on-arvo
  |=  [=wire =sign-arvo]
  ^-  (quip card _this)
  |^
  ?+  wire  (on-arvo:def wire sign-arvo)
      [%eyre *]  `this
  ::
      [%fetch @ @ ~]
    =/  eid=@ta  i.t.wire
    =/  idx=@ud  (slav %ud i.t.t.wire)
    ?>  ?=([%iris %http-response *] sign-arvo)
    (handle-iris-response eid idx +>.sign-arvo)
  ==
  ::
  ++  handle-iris-response
    |=  [eid=@ta idx=@ud res=client-response:iris]
    ^-  (quip card _this)
    ?.  (~(has by fetches) eid)
      `this
    ?.  ?=(%finished -.res)
      `this
    =/  batch  (~(got by fetches) eid)
    =/  url=@t  (snag idx urls.batch)
    =/  result=fetch-result
      =/  status  status-code.response-header.res
      =/  headers=(list [@t @t])  headers.response-header.res
      =/  body=@t
        ?~  full-file.res  ''
        =/  bod=octs  data.u.full-file.res
        ?:  =(0 p.bod)  ''
        (en:base64:mimes:html bod)
      [%ok status headers body]
    =.  done.batch  (~(put by done.batch) idx result)
    =.  fetches  (~(put by fetches) eid batch)
    ?.  =(~(wyt by done.batch) total.batch)
      `this
    =/  results=(list json)
      =|  i=@ud
      |-
      ?:  =(i total.batch)  ~
      =/  u=@t  (snag i urls.batch)
      =/  r=fetch-result  (~(got by done.batch) i)
      :_  $(i +(i))
      ?-  -.r
          %ok
        %-  pairs:enjs:format
        :~  ['url' s+u]
            ['status' (numb:enjs:format status.r)]
            ['headers' a+(turn headers.r |=([k=@t v=@t] a+~[s+k s+v]))]
            ['body' s+body.r]
        ==
          %fail
        (pairs:enjs:format ~[['url' s+u] ['error' s+msg.r]])
      ==
    =/  resp-body=@t  (en:json:html a+results)
    =.  fetches  (~(del by fetches) eid)
    :_  this
    (give-http eid 200 ~[['content-type' 'application/json']] (some (as-octs:mimes:html resp-body)))
  --
::
++  on-fail  on-fail:def
--
::
::  --- pure helpers ---
::
|%
++  give-http
  |=  [eyre-id=@ta status=@ud headers=(list [@t @t]) body=(unit octs)]
  ^-  (list card)
  =/  hp=path  /http-response/[eyre-id]
  :~  [%give %fact ~[hp] %http-response-header !>(`response-header:http`[status headers])]
      [%give %fact ~[hp] %http-response-data !>(`(unit octs)`body)]
      [%give %kick ~[hp] ~]
  ==
::
++  parse-action
  |=  jon=json
  ^-  action
  ?>  ?=([%o *] jon)
  =/  outer=(map @t json)  p.jon
  ?:  (~(has by outer) 'save')
    =/  val=json  (~(got by outer) 'save')
    ?>  ?=([%o *] val)
    =/  m=(map @t json)  p.val
    :*  %save
        (so:dejs:format (~(got by m) 'id'))
        (so:dejs:format (~(got by m) 'url'))
        (so:dejs:format (~(got by m) 'title'))
        ((ar:dejs:format so:dejs:format) (~(got by m) 'tags'))
        (so:dejs:format (~(got by m) 's3-path'))
    ==
  ?:  (~(has by outer) 'delete')
    =/  val=json  (~(got by outer) 'delete')
    ?>  ?=([%o *] val)
    =/  m=(map @t json)  p.val
    [%delete (so:dejs:format (~(got by m) 'id'))]
  ?:  (~(has by outer) 'add-tag')
    =/  val=json  (~(got by outer) 'add-tag')
    ?>  ?=([%o *] val)
    =/  m=(map @t json)  p.val
    :+  %add-tag
      (so:dejs:format (~(got by m) 'id'))
    (so:dejs:format (~(got by m) 'tag'))
  ?:  (~(has by outer) 'remove-tag')
    =/  val=json  (~(got by outer) 'remove-tag')
    ?>  ?=([%o *] val)
    =/  m=(map @t json)  p.val
    :+  %remove-tag
      (so:dejs:format (~(got by m) 'id'))
    (so:dejs:format (~(got by m) 'tag'))
  !!
::
++  to-unix
  |=  d=@da
  ^-  @ud
  ?:  (lth d ~1970.1.1)  0
  (div (sub d ~1970.1.1) ~s1)
::
++  bookmark-to-json
  |=  [=bookmark-id bm=bookmark]
  ^-  json
  %-  pairs:enjs:format
  :~  ['type' s+'bookmark']
      ['id' s+bookmark-id]
      ['url' s+url.bm]
      ['title' s+title.bm]
      ['tags' a+(turn ~(tap in tags.bm) |=(t=@t s+t))]
      ['s3Path' s+s3-path.bm]
      ['added' (numb:enjs:format (to-unix added.bm))]
  ==
::
++  all-bookmarks-json
  |=  bms=(list [bookmark-id bookmark])
  ^-  json
  %-  pairs:enjs:format
  :~  ['type' s+'all']
      ['bookmarks' a+(turn bms |=([=bookmark-id bm=bookmark] (bookmark-to-json bookmark-id bm)))]
  ==
::
++  del-to-json
  |=  =bookmark-id
  ^-  json
  (pairs:enjs:format ~[['type' s+'delete'] ['id' s+bookmark-id]])
::
++  scry-s3-config
  |=  =bowl:gall
  ^-  json
  =/  get-str
    |=  [=json keys=(list @t)]
    ^-  @t
    ?~  keys  ?:(?=([%s *] json) p.json '')
    ?.  ?=([%o *] json)  ''
    =/  v  (~(get by p.json) i.keys)
    ?~  v  ''
    $(json u.v, keys t.keys)
  =/  cred=json
    .^(json %gx /(scot %p our.bowl)/storage/(scot %da now.bowl)/credentials/json)
  =/  conf=json
    .^(json %gx /(scot %p our.bowl)/storage/(scot %da now.bowl)/configuration/json)
  %-  pairs:enjs:format
  :~  ['endpoint' s+(get-str cred ~['storage-update' 'credentials' 'endpoint'])]
      ['accessKeyId' s+(get-str cred ~['storage-update' 'credentials' 'accessKeyId'])]
      ['secretAccessKey' s+(get-str cred ~['storage-update' 'credentials' 'secretAccessKey'])]
      ['bucket' s+(get-str conf ~['storage-update' 'configuration' 'currentBucket'])]
      ['region' s+(get-str conf ~['storage-update' 'configuration' 'region'])]
  ==
--
