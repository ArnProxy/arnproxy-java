package com.arnproxy.sdk;

import com.google.gson.*;
import java.io.*;
import java.lang.reflect.Array;
import java.math.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.*;
import java.security.*;
import java.util.*;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

/** Server-side client. Never embed an API key in a public app. */
public class Client {
 public static final String VERSION="1.1.1",BASE="https://www.arnproxy.com/account/api/v1/";
 private static final int MAX=2*1024*1024;
 private static final Gson JSON=new GsonBuilder().setStrictness(Strictness.STRICT).serializeNulls().create();
 private static final Pattern KEY=Pattern.compile("(?:[A-Za-z0-9]{32}|arnp_[a-f0-9]{16}_[a-f0-9]{64})"),OPERATION=Pattern.compile("[A-Za-z0-9_-]{16,100}"),REQUEST=Pattern.compile("[a-f0-9]{24}");
 private static final Map<String,JsonObject> RESOURCES=loadResources();
 private final transient String apiKey;
 private final Options options;
 /** Client guards are separate from server-side account permissions. */
 public record Options(boolean allowWrites,boolean allowProviderReads,int timeoutSeconds) {
  public Options { if(timeoutSeconds<1||timeoutSeconds>60)throw new ApiException("INVALID_CLIENT_OPTIONS"); }
  public static Options defaults(){return new Options(false,false,20);}
 }
 public Client(String apiKey){this(apiKey,Options.defaults());}
 public Client(String apiKey,Options options){if(apiKey==null||!KEY.matcher(apiKey).matches())throw new ApiException("INVALID_KEY_FORMAT");if(options==null)throw new ApiException("INVALID_CLIENT_OPTIONS");this.apiKey=apiKey;this.options=options;}
 @Override public final String toString(){return "ARNPROXY Client(key=REDACTED)";}
 private static Map<String,JsonObject> loadResources(){
  try(InputStream input=Client.class.getResourceAsStream("resources.json")){
   if(input==null)throw new IllegalArgumentException();JsonObject contract=JSON.fromJson(decode(input.readNBytes(100000)),JsonObject.class);if(!BASE.equals(contract.get("base").getAsString()))throw new IllegalArgumentException();Map<String,JsonObject> result=new HashMap<>();for(var e:contract.getAsJsonObject("resources").entrySet())result.put(e.getKey(),e.getValue().getAsJsonObject());if(result.size()!=77)throw new IllegalArgumentException();return Collections.unmodifiableMap(result);
  }catch(Exception e){throw new ApiException("CLIENT_CONTRACT_INVALID");}
 }
 public JsonObject account(){return request("account",Map.of(),null);}
 public JsonObject capabilities(){return request("capabilities",Map.of(),null);}
 public JsonObject request(String resource,Map<String,?> parameters){return request(resource,parameters,null);}
 public JsonObject request(String resource,Map<String,?> parameters,String operationKey){
  JsonObject spec=RESOURCES.get(resource);if(spec==null)throw new ApiException("UNKNOWN_RESOURCE");
  Map<String,Object> params=new LinkedHashMap<>();if(parameters!=null)for(var entry:parameters.entrySet()){if(entry.getKey()==null||!validUnicode(entry.getKey()))throw new ApiException("INVALID_PARAMETERS");params.put(entry.getKey(),entry.getValue());}
  if(params.containsKey("resource"))throw new ApiException("INVALID_PARAMETERS");if(spec.get("disabled").getAsBoolean())throw new ApiException("DISABLED_RESOURCE");
  boolean write=spec.get("write").getAsBoolean();if(write&&!options.allowWrites())throw new ApiException("WRITES_DISABLED");if(spec.get("provider_read").getAsBoolean()&&!options.allowProviderReads())throw new ApiException("PROVIDER_READS_DISABLED");
  boolean idempotency=spec.get("idempotency").getAsBoolean();if(idempotency&&(operationKey==null||!OPERATION.matcher(operationKey).matches()))throw new ApiException("OPERATION_KEY_REQUIRED");if(!idempotency&&operationKey!=null)throw new ApiException("UNEXPECTED_OPERATION_KEY");
  Map<String,String> headers=new LinkedHashMap<>();headers.put("Authorization","Bearer "+apiKey);headers.put("Accept","application/json");headers.put("User-Agent","ARNPROXY-Java/"+VERSION);if(idempotency)headers.put("Idempotency-Key",operationKey);
  String method=spec.get("method").getAsString(),path=spec.get("path").getAsString();
  if(path.contains("{id}")){Object value=params.remove("id");String id=scalar(value);if(value instanceof Boolean||id==null||!id.matches("[1-9][0-9]{0,9}")||new BigInteger(id).compareTo(BigInteger.valueOf(2147483647))>0)throw new ApiException("INVALID_ROUTE_ID");path=path.replace("{id}",id);}
  byte[] body=null;
  if(method.equals("GET")){StringJoiner query=new StringJoiner("&");for(var entry:params.entrySet()){String value=scalar(entry.getValue());if(value==null)throw new ApiException("INVALID_QUERY_VALUE");query.add(URLEncoder.encode(entry.getKey(),StandardCharsets.UTF_8)+"="+URLEncoder.encode(value,StandardCharsets.UTF_8));}if(query.length()>0)path+="?"+query;}
  else{try{if(!jsonValue(params,0))throw new IllegalArgumentException();body=JSON.toJson(params).getBytes(StandardCharsets.UTF_8);}catch(Exception e){throw new ApiException("INVALID_JSON_BODY");}if(body.length>MAX)throw new ApiException("REQUEST_TOO_LARGE");headers.put("Content-Type","application/json");}
  Raw raw;try{raw=send(method,"/account/api/v1/"+path,headers,body);}catch(ApiException e){throw new ApiException(e.code,null,null,null,write);}catch(Exception e){throw new ApiException("TRANSPORT_ERROR",null,null,null,write);}
  if(raw.status>=300&&raw.status<400)throw new ApiException("REDIRECT_BLOCKED",raw.status,null,null,write);
  Integer retry=null;String retryValue=raw.retryAfter;if(retryValue!=null&&retryValue.matches("[0-9]{1,5}")&&Integer.parseInt(retryValue)<=86400)retry=Integer.valueOf(retryValue);
  if(raw.body==null||raw.body.length>MAX)throw new ApiException("RESPONSE_TOO_LARGE",raw.status,null,retry,write);
  JsonObject result;String requestId;
  try{result=JSON.fromJson(decode(raw.body),JsonObject.class);if(result==null||!result.has("ok")||!result.get("ok").isJsonPrimitive()||!result.get("ok").getAsJsonPrimitive().isBoolean())throw new IllegalArgumentException();JsonElement id=result.getAsJsonObject("meta").get("request_id");if(id==null||!id.isJsonPrimitive()||!id.getAsJsonPrimitive().isString()||!REQUEST.matcher(id.getAsString()).matches())throw new IllegalArgumentException();requestId=id.getAsString();}catch(Exception e){throw new ApiException("INVALID_API_RESPONSE",raw.status,null,retry,write);}
  if(raw.status<200||raw.status>=300||!result.get("ok").getAsBoolean()){String code="API_HTTP_ERROR";try{JsonElement value=result.getAsJsonObject("error").get("code");if(value.isJsonPrimitive()&&value.getAsJsonPrimitive().isString()&&value.getAsString().matches("[A-Z][A-Z0-9_]{0,79}"))code=value.getAsString();}catch(Exception ignored){}throw new ApiException(code,raw.status,requestId,retry,write&&raw.status>=500);}
  if(!result.has("data"))throw new ApiException("INVALID_API_RESPONSE",raw.status,requestId,retry,write);return result;
 }
 // Override only for isolated tests. Normal construction has no custom URL,
 // proxy or insecure-TLS option, and no retry or polling implementation.
 protected record Raw(int status,String retryAfter,byte[] body) {}
 protected Raw send(String method,String path,Map<String,String> headers,byte[] body) throws Exception {
  HttpsURLConnection connection=(HttpsURLConnection)new URI("https://www.arnproxy.com"+path).toURL().openConnection(Proxy.NO_PROXY);long deadline=System.nanoTime()+options.timeoutSeconds()*1_000_000_000L;
  try{
   connection.setInstanceFollowRedirects(false);connection.setUseCaches(false);connection.setConnectTimeout(options.timeoutSeconds()*1000);connection.setReadTimeout(options.timeoutSeconds()*1000);connection.setRequestMethod(method);connection.setRequestProperty("Connection","close");for(var e:headers.entrySet())connection.setRequestProperty(e.getKey(),e.getValue());
   // Fixed-length streaming prevents replay of a failed POST body by the JDK.
   if(body!=null){connection.setDoOutput(true);connection.setFixedLengthStreamingMode(body.length);try(OutputStream output=connection.getOutputStream()){output.write(body);}}
   int status=connection.getResponseCode();InputStream stream=status>=400?connection.getErrorStream():connection.getInputStream();ByteArrayOutputStream bytes=new ByteArrayOutputStream();
   if(stream!=null)try(InputStream input=stream){byte[] buffer=new byte[16384];while(true){long remaining=(deadline-System.nanoTime())/1_000_000L;if(remaining<=0)throw new ApiException("TRANSPORT_TIMEOUT");connection.setReadTimeout((int)Math.min(remaining,Integer.MAX_VALUE));int n=input.read(buffer);if(n<0)break;if(bytes.size()+n>MAX)throw new ApiException("RESPONSE_TOO_LARGE");bytes.write(buffer,0,n);}}
   return new Raw(status,connection.getHeaderField("Retry-After"),bytes.toByteArray());
  }finally{connection.disconnect();}
 }
 private static String decode(byte[] value) throws CharacterCodingException{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(value)).toString();}
 private static boolean validUnicode(String s){for(int i=0;i<s.length();i++){char c=s.charAt(i);if(Character.isHighSurrogate(c)){if(++i>=s.length()||!Character.isLowSurrogate(s.charAt(i)))return false;}else if(Character.isLowSurrogate(c))return false;}return true;}
 private static String scalar(Object value){if(value instanceof String s)return validUnicode(s)?s:null;if(value instanceof Boolean b)return b?"1":"0";if(value instanceof Byte||value instanceof Short||value instanceof Integer||value instanceof Long||value instanceof BigInteger)return value.toString();return null;}
 private static boolean jsonValue(Object value,int depth){if(depth>32)return false;if(value==null)return true;if(value instanceof String s)return validUnicode(s);if(scalar(value)!=null)return true;if(value instanceof BigDecimal)return true;if(value instanceof Double d)return Double.isFinite(d);if(value instanceof Float f)return Float.isFinite(f);if(value instanceof Map<?,?> map){for(var e:map.entrySet())if(!(e.getKey() instanceof String s)||!validUnicode(s)||!jsonValue(e.getValue(),depth+1))return false;return true;}if(value instanceof List<?> list){for(Object item:list)if(!jsonValue(item,depth+1))return false;return true;}if(value.getClass().isArray()){for(int i=0;i<Array.getLength(value);i++)if(!jsonValue(Array.get(value,i),depth+1))return false;return true;}return false;}
 /** Authenticate original bytes; deduplicate event IDs durably yourself. */
 public static JsonObject verifyWebhook(byte[] raw,Map<String,String> headers,String signingSecret,long now){
  try{
   if(raw==null||raw.length>4096||headers==null)throw new IllegalArgumentException();Map<String,String> values=new HashMap<>();for(var entry:headers.entrySet()){String key=entry.getKey().toLowerCase(Locale.ROOT);if(Set.of("webhook-id","webhook-timestamp","webhook-signature").contains(key)){if(values.putIfAbsent(key,entry.getValue())!=null||entry.getValue()==null)throw new IllegalArgumentException();}}
   String id=values.get("webhook-id"),timestamp=values.get("webhook-timestamp"),signature=values.get("webhook-signature");if(id==null||!id.matches("evt_[a-f0-9]{32}")||timestamp==null||!timestamp.matches("[1-9][0-9]{0,11}")||signature==null||signature.length()>1024||now<1||now>999999999999L||Math.abs(now-Long.parseLong(timestamp))>300)throw new IllegalArgumentException();
   if(signingSecret==null||!signingSecret.matches("whsec_[A-Za-z0-9+/]{43}="))throw new IllegalArgumentException();byte[] key=Base64.getDecoder().decode(signingSecret.substring(6));if(key.length!=32||!Base64.getEncoder().encodeToString(key).equals(signingSecret.substring(6)))throw new IllegalArgumentException();
   Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key,"HmacSHA256"));mac.update((id+"."+timestamp+".").getBytes(StandardCharsets.US_ASCII));byte[] expected=mac.doFinal(raw);boolean valid=false;for(String token:signature.split("\\s+"))if(token.matches("v1,[A-Za-z0-9+/]{43}="))valid=MessageDigest.isEqual(expected,Base64.getDecoder().decode(token.substring(3)))|valid;if(!valid)throw new IllegalArgumentException();
   JsonObject event=JSON.fromJson(decode(raw),JsonObject.class);if(event==null||!event.get("id").isJsonPrimitive()||!event.get("id").getAsJsonPrimitive().isString()||!id.equals(event.get("id").getAsString())||!event.get("api_version").isJsonPrimitive()||!event.get("api_version").getAsJsonPrimitive().isString()||!"1".equals(event.get("api_version").getAsString())||!event.get("data").isJsonObject()||!event.get("type").isJsonPrimitive()||!event.get("type").getAsJsonPrimitive().isString())throw new IllegalArgumentException();return event;
  }catch(Exception e){throw new ApiException("WEBHOOK_VERIFICATION_FAILED");}
 }
}
