package com.arnproxy.sdk;

import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.net.URI;
import com.arnproxy.sdk.Client.Options;

/** Isolated contract tests. No real API key or network call. */
public final class ClientTest {
 static final String KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",OP="op_synthetic_1234567890",OK="{\"ok\":true,\"data\":{\"id\":2},\"meta\":{\"request_id\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"}}";
 static int checks=0;
 static void check(boolean value){if(!value)throw new AssertionError("check "+checks);checks++;}
 static ApiException error(Runnable r,String code){try{r.run();throw new AssertionError("no error "+code);}catch(ApiException e){check(e.code.equals(code));check(!e.toString().contains(KEY));check(e.getCause()==null);return e;}}
 static class Mock extends Client {
  int calls=0,status=200;String raw=OK,retry=null,method,path;Map<String,String> headers;byte[] body;boolean fail=false;
  Mock(){this(new Options(true,true,20));}Mock(Options o){super(KEY,o);}
  @Override protected Raw send(String m,String p,Map<String,String> h,byte[] b)throws Exception{calls++;method=m;path=p;headers=h;body=b;if(fail)throw new Exception("secret "+KEY);return new Raw(status,retry,raw.getBytes(StandardCharsets.UTF_8));}
 }
 public static void main(String[] args)throws Exception {
  Gson json=new Gson();JsonObject contract=json.fromJson(Files.readString(Path.of(args[0])),JsonObject.class);JsonObject fixtures=json.fromJson(Files.readString(Path.of(args[1])),JsonObject.class);
  check(contract.getAsJsonObject("resources").size()==77);
  for(var entry:contract.getAsJsonObject("resources").entrySet()){
   String name=entry.getKey();JsonObject spec=entry.getValue().getAsJsonObject();Map<String,Object> params=new LinkedHashMap<>();String path=spec.get("path").getAsString();if(path.contains("{id}"))params.put("id",123);params.put("q","ü & = ? /");String key=spec.get("idempotency").getAsBoolean()?OP:null;Mock c=new Mock();
   if(spec.get("disabled").getAsBoolean()){error(()->c.request(name,params,key),"DISABLED_RESOURCE");check(c.calls==0);continue;}
   check(c.request(name,params,key).getAsJsonObject("data").get("id").getAsInt()==2);check(c.calls==1);check(c.method.equals(spec.get("method").getAsString()));check(URI.create(c.path).getPath().equals("/account/api/v1/"+path.replace("{id}","123")));check(!c.path.contains(KEY));check(c.headers.get("Authorization").equals("Bearer "+KEY));check(Objects.equals(c.headers.get("Idempotency-Key"),key));
   if(c.method.equals("GET")){check(c.body==null);check(java.net.URLDecoder.decode(URI.create(c.path).getRawQuery(),StandardCharsets.UTF_8).equals("q=ü & = ? /"));}else check(json.fromJson(new String(c.body,StandardCharsets.UTF_8),JsonObject.class).get("q").getAsString().equals(params.get("q")));
   if(path.contains("{id}"))check(params.containsKey("id"));Mock guard=new Mock(Options.defaults());boolean write=spec.get("write").getAsBoolean();if(write||spec.get("provider_read").getAsBoolean()){error(()->guard.request(name,params,key),write?"WRITES_DISABLED":"PROVIDER_READS_DISABLED");check(guard.calls==0);}if(key!=null){error(()->c.request(name,params,null),"OPERATION_KEY_REQUIRED");check(c.calls==1);}
  }
  for(String key:List.of("",KEY+"\n"," "+KEY,"x".repeat(31)))error(()->new Client(key),"INVALID_KEY_FORMAT");error(()->new Client(KEY,new Options(false,false,0)),"INVALID_CLIENT_OPTIONS");Mock c=new Mock();
  error(()->c.request("account",Map.of("resource","purchase")),"INVALID_PARAMETERS");error(()->c.request("proxy",Map.of("id","1/../../x")),"INVALID_ROUTE_ID");error(()->c.request("proxy",Map.of("id",true)),"INVALID_ROUTE_ID");error(()->c.request("orders",Map.of("q",List.of(1,2))),"INVALID_QUERY_VALUE");error(()->c.request("quote",Map.of("n",Double.NaN)),"INVALID_JSON_BODY");error(()->c.request("quote",Map.of("x","x".repeat(2*1024*1024))),"REQUEST_TOO_LARGE");error(()->c.request("account",Map.of(),OP),"UNEXPECTED_OPERATION_KEY");
  c.status=302;c.raw="";int before=c.calls;check(!error(c::account,"REDIRECT_BLOCKED").uncertain);check(c.calls==before+1);
  c.status=429;c.retry="12";c.raw="{\"ok\":false,\"error\":{\"code\":\"RATE_LIMITED\"},\"meta\":{\"request_id\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"}}";ApiException err=error(c::account,"RATE_LIMITED");check(err.httpStatus==429&&err.retryAfter==12&&err.requestId.length()==24);
  c.status=500;c.raw="<html>secret</html>";check(error(()->c.request("purchase",Map.of(),OP),"INVALID_API_RESPONSE").uncertain);c.fail=true;before=c.calls;check(error(()->c.request("purchase",Map.of(),OP),"TRANSPORT_ERROR").uncertain);check(c.calls==before+1);c.fail=false;c.status=200;
  for(String bad:List.of("{\"ok\":\"true\",\"data\":{},\"meta\":{\"request_id\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"}}",OK+" {}","{\"ok\":true,\"meta\":{\"request_id\":\"aaaaaaaaaaaaaaaaaaaaaaaa\"}}")){c.raw=bad;error(c::account,"INVALID_API_RESPONSE");}
  c.raw="x".repeat(2*1024*1024+1);error(c::account,"RESPONSE_TOO_LARGE");c.raw=OK;check(c.request("quote",Map.of("ids",new int[]{1,2})).get("ok").getAsBoolean());check(!c.toString().contains(KEY));check(!json.toJson(new Client(KEY)).contains(KEY));
  for(JsonElement item:fixtures.getAsJsonArray("vectors")){JsonObject v=item.getAsJsonObject();Map<String,String> headers=new LinkedHashMap<>();for(var e:v.getAsJsonObject("headers").entrySet())headers.put(e.getKey(),e.getValue().getAsString());boolean accepted;try{Client.verifyWebhook(v.get("body").getAsString().getBytes(StandardCharsets.UTF_8),headers,v.get("secret").getAsString(),v.get("now").getAsLong());accepted=true;}catch(ApiException e){check(e.code.equals("WEBHOOK_VERIFICATION_FAILED"));accepted=false;}check(accepted==v.get("valid").getAsBoolean());}
  System.out.println("{\"language\":\"java\",\"status\":\"PASSED_OFFLINE_CONTRACT_AND_WEBHOOKS\",\"resources\":77,\"checks\":"+checks+",\"network_calls\":0}");
 }
}
