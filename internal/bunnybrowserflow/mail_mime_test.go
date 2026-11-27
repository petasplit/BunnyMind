package bunnybrowserflow

import (
 "encoding/base64"
 "strings"
 "testing"
)
func TestReadMailTextPlainQuotedPrintable(t *testing.T){
 raw:="From: verify@example.com\r\nTo: test@example.test\r\n"+
  "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"+
  "Your verification code is =37=33=39=32=31=35"
 body,err:=readMailText([]byte(raw))
 if err!=nil||!strings.Contains(body,"739215"){t.Fatalf("quoted-printable verification code lost: %q %v",body,err)}
}
func TestReadMailTextBase64HTML(t *testing.T){
 encoded:=base64.StdEncoding.EncodeToString([]byte("<html><body><p>Code: <b>763129</b></p></body></html>"))
 raw:="From: verify@example.com\r\nTo: test@example.test\r\n"+
  "Content-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n"+encoded
 body,err:=readMailText([]byte(raw))
 if err!=nil||!strings.Contains(body,"763129")||strings.Contains(body,"<b>"){t.Fatalf("HTML decoding failed: %q %v",body,err)}
}
func TestReadMailTextMultipartPrefersPlain(t *testing.T){
 raw:="MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=\"bm-boundary\"\r\n\r\n"+
  "--bm-boundary\r\nContent-Type: text/plain\r\n\r\nYour code: 645219\r\n"+
  "--bm-boundary\r\nContent-Type: text/html\r\n\r\n<html><p>not the preferred part 123456</p></html>\r\n"+
  "--bm-boundary--\r\n"
 body,err:=readMailText([]byte(raw))
 if err!=nil||!strings.Contains(body,"645219")||strings.Contains(body,"123456"){t.Fatalf("wrong MIME part selected: %q %v",body,err)}
}
func TestReadMailTextRejectsOversizeAndAttachment(t *testing.T){
 if _,err:=readMailText([]byte(strings.Repeat("A",maxMailBytes+1)));err==nil{t.Fatal("oversized email accepted")}
 raw:="Content-Type: application/octet-stream\r\n\r\npassword=secret"
 if _,err:=readMailText([]byte(raw));err==nil{t.Fatal("non-text attachment treated as OTP message")}
}
