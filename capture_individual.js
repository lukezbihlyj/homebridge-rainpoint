'use strict';
Java.perform(function () {
  var SNA = Java.use("com.thingclips.smart.security.jni.SecureNativeApi");
  var JS = Java.use("java.lang.String");
  var AT = Java.use("android.app.ActivityThread");
  var TN = Java.use("com.thingclips.smart.android.network.ThingSmartNetWork");
  var TNS = Java.use("com.thingclips.sdk.network.ThingNetworkSecurity");
  var a=0,d=false;
  var t=setInterval(function(){if(d)return;a++;var p=TN.mAppId.value,app=AT.currentApplication();if(p===null||app===null){if(a%10===0)console.log("[CAP] wait "+a);return;}d=true;clearInterval(t);console.log("[CAP] appId="+p+" mD="+TN.mD.value);var eb0=JS.$new("").getBytes("UTF-8"),mD=TN.mD.value;
  try{var b0=JS.$new("z2z8A5Azz81z6A88").getBytes("UTF-8");var r0=SNA.doCommandNative(app,2,b0,eb0,mD);console.log("[R] z2z8A5Azz81z6A88 -> "+(r0?r0.toString():"null"));}catch(e){console.log("[R] z2z8A5Azz81z6A88 err: "+e);}
  try{var b1=JS.$new("z2z8A5Azz81z6A88").getBytes("UTF-8");var r1=SNA.doCommandNative(app,2,b1,eb0,mD);console.log("[R] z2z8A5Azz81z6A88 -> "+(r1?r1.toString():"null"));}catch(e){console.log("[R] z2z8A5Azz81z6A88 err: "+e);}
  try{var b2=JS.$new("AAAAAAAAAAAAAAAA").getBytes("UTF-8");var r2=SNA.doCommandNative(app,2,b2,eb0,mD);console.log("[R] AAAAAAAAAAAAAAAA -> "+(r2?r2.toString():"null"));}catch(e){console.log("[R] AAAAAAAAAAAAAAAA err: "+e);}
  try{var b3=JS.$new("BBBBBBBBBBBBBBBB").getBytes("UTF-8");var r3=SNA.doCommandNative(app,2,b3,eb0,mD);console.log("[R] BBBBBBBBBBBBBBBB -> "+(r3?r3.toString():"null"));}catch(e){console.log("[R] BBBBBBBBBBBBBBBB err: "+e);}
  try{var b4=JS.$new("0000000000000000").getBytes("UTF-8");var r4=SNA.doCommandNative(app,2,b4,eb0,mD);console.log("[R] 0000000000000000 -> "+(r4?r4.toString():"null"));}catch(e){console.log("[R] 0000000000000000 err: "+e);}
  try{var b5=JS.$new("ffffffffffffffff").getBytes("UTF-8");var r5=SNA.doCommandNative(app,2,b5,eb0,mD);console.log("[R] ffffffffffffffff -> "+(r5?r5.toString():"null"));}catch(e){console.log("[R] ffffffffffffffff err: "+e);}
  try{var b6=JS.$new("1111111111111111").getBytes("UTF-8");var r6=SNA.doCommandNative(app,2,b6,eb0,mD);console.log("[R] 1111111111111111 -> "+(r6?r6.toString():"null"));}catch(e){console.log("[R] 1111111111111111 err: "+e);}
  try{var b7=JS.$new("2222222222222222").getBytes("UTF-8");var r7=SNA.doCommandNative(app,2,b7,eb0,mD);console.log("[R] 2222222222222222 -> "+(r7?r7.toString():"null"));}catch(e){console.log("[R] 2222222222222222 err: "+e);}
  try{var b8=JS.$new("1234567890abcdef").getBytes("UTF-8");var r8=SNA.doCommandNative(app,2,b8,eb0,mD);console.log("[R] 1234567890abcdef -> "+(r8?r8.toString():"null"));}catch(e){console.log("[R] 1234567890abcdef err: "+e);}
  try{var b9=JS.$new("0123456789abcdef").getBytes("UTF-8");var r9=SNA.doCommandNative(app,2,b9,eb0,mD);console.log("[R] 0123456789abcdef -> "+(r9?r9.toString():"null"));}catch(e){console.log("[R] 0123456789abcdef err: "+e);}
  try{var b10=JS.$new("BAAAAAAAAAAAAAAA").getBytes("UTF-8");var r10=SNA.doCommandNative(app,2,b10,eb0,mD);console.log("[R] BAAAAAAAAAAAAAAA -> "+(r10?r10.toString():"null"));}catch(e){console.log("[R] BAAAAAAAAAAAAAAA err: "+e);}
  try{var b11=JS.$new("ABAAAAAAAAAAAAAA").getBytes("UTF-8");var r11=SNA.doCommandNative(app,2,b11,eb0,mD);console.log("[R] ABAAAAAAAAAAAAAA -> "+(r11?r11.toString():"null"));}catch(e){console.log("[R] ABAAAAAAAAAAAAAA err: "+e);}
  try{var b12=JS.$new("AABAAAAAAAAAAAAA").getBytes("UTF-8");var r12=SNA.doCommandNative(app,2,b12,eb0,mD);console.log("[R] AABAAAAAAAAAAAAA -> "+(r12?r12.toString():"null"));}catch(e){console.log("[R] AABAAAAAAAAAAAAA err: "+e);}
  try{var b13=JS.$new("AAAAAAAAAAAAAAAB").getBytes("UTF-8");var r13=SNA.doCommandNative(app,2,b13,eb0,mD);console.log("[R] AAAAAAAAAAAAAAAB -> "+(r13?r13.toString():"null"));}catch(e){console.log("[R] AAAAAAAAAAAAAAAB err: "+e);}
  try{var b14=JS.$new("A").getBytes("UTF-8");var r14=SNA.doCommandNative(app,2,b14,eb0,mD);console.log("[R] A -> "+(r14?r14.toString():"null"));}catch(e){console.log("[R] A err: "+e);}
  try{var b15=JS.$new("AA").getBytes("UTF-8");var r15=SNA.doCommandNative(app,2,b15,eb0,mD);console.log("[R] AA -> "+(r15?r15.toString():"null"));}catch(e){console.log("[R] AA err: "+e);}
  try{var b16=JS.$new("AAA").getBytes("UTF-8");var r16=SNA.doCommandNative(app,2,b16,eb0,mD);console.log("[R] AAA -> "+(r16?r16.toString():"null"));}catch(e){console.log("[R] AAA err: "+e);}
  try{var b17=JS.$new("AAAA").getBytes("UTF-8");var r17=SNA.doCommandNative(app,2,b17,eb0,mD);console.log("[R] AAAA -> "+(r17?r17.toString():"null"));}catch(e){console.log("[R] AAAA err: "+e);}
  try{var b18=JS.$new("AAAAAAAA").getBytes("UTF-8");var r18=SNA.doCommandNative(app,2,b18,eb0,mD);console.log("[R] AAAAAAAA -> "+(r18?r18.toString():"null"));}catch(e){console.log("[R] AAAAAAAA err: "+e);}
  try{var b19=JS.$new("AAAAAAAAAAAAAAAAA").getBytes("UTF-8");var r19=SNA.doCommandNative(app,2,b19,eb0,mD);console.log("[R] AAAAAAAAAAAAAAAAA -> "+(r19?r19.toString():"null"));}catch(e){console.log("[R] AAAAAAAAAAAAAAAAA err: "+e);}
  try{var b20=JS.$new("").getBytes("UTF-8");var r20=SNA.doCommandNative(app,2,b20,eb0,mD);console.log("[R]  -> "+(r20?r20.toString():"null"));}catch(e){console.log("[R]  err: "+e);}
  try{var b21=JS.$new("test").getBytes("UTF-8");var r21=SNA.doCommandNative(app,2,b21,eb0,mD);console.log("[R] test -> "+(r21?r21.toString():"null"));}catch(e){console.log("[R] test err: "+e);}
  try{var b22=JS.$new("a").getBytes("UTF-8");var r22=SNA.doCommandNative(app,2,b22,eb0,mD);console.log("[R] a -> "+(r22?r22.toString():"null"));}catch(e){console.log("[R] a err: "+e);}
  try{var b23=JS.$new("deadbeefdeadbeef").getBytes("UTF-8");var r23=SNA.doCommandNative(app,2,b23,eb0,mD);console.log("[R] deadbeefdeadbeef -> "+(r23?r23.toString():"null"));}catch(e){console.log("[R] deadbeefdeadbeef err: "+e);}
  try{var b24=JS.$new("z1z1z1z1z1z1z1z1").getBytes("UTF-8");var r24=SNA.doCommandNative(app,2,b24,eb0,mD);console.log("[R] z1z1z1z1z1z1z1z1 -> "+(r24?r24.toString():"null"));}catch(e){console.log("[R] z1z1z1z1z1z1z1z1 err: "+e);}
  try{var b25=JS.$new("AZAZAZAZAZAZAZAZ").getBytes("UTF-8");var r25=SNA.doCommandNative(app,2,b25,eb0,mD);console.log("[R] AZAZAZAZAZAZAZAZ -> "+(r25?r25.toString():"null"));}catch(e){console.log("[R] AZAZAZAZAZAZAZAZ err: "+e);}
  try{var ck=TNS.getChKey(app,JS.$new(p).getBytes("UTF-8"));console.log("[R] getChKey="+ck);}catch(e){console.log("[R] getChKey err: "+e);}
  console.log("[CAP] DONE");
},500);
});
