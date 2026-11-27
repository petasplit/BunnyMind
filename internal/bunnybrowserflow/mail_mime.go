package bunnybrowserflow

import (
 "bytes"
 "encoding/base64"
 "errors"
 "html"
 "io"
 "mime"
 "mime/multipart"
 "mime/quotedprintable"
 "net/mail"
 "regexp"
 "strings"
)

// The IMAP adapter parses only small text parts and never returns the mail
// body to a caller. Attachments and non-text parts are intentionally ignored.
const maxMailBytes=32768
var htmlTags=regexp.MustCompile(`<[^>]+>`)

func decodedBody(reader io.Reader,encoding string)(string,error){
 switch strings.ToLower(strings.TrimSpace(encoding)){
 case "base64":reader=base64.NewDecoder(base64.StdEncoding,reader)
 case "quoted-printable":reader=quotedprintable.NewReader(reader)
 case "","7bit","8bit","binary":
 default:return "",errors.New("unsupported mail transfer encoding")
 }
 b,err:=io.ReadAll(io.LimitReader(reader,maxMailBytes+1))
 if err!=nil||len(b)>maxMailBytes{return "",errors.New("mail part exceeded safety bound")}
 return string(b),nil
}
func readMailText(raw []byte)(string,error){
 if len(raw)==0||len(raw)>maxMailBytes{return "",errors.New("mail message size not allowed")}
 msg,err:=mail.ReadMessage(bytes.NewReader(raw))
 if err!=nil{return "",errors.New("unparseable mail headers")}
 mediaType,parameters,_:=mime.ParseMediaType(msg.Header.Get("Content-Type"))
 if mediaType==""{mediaType="text/plain"}
 if strings.HasPrefix(mediaType,"multipart/"){
  mr:=multipart.NewReader(msg.Body,parameters["boundary"])
  var htmlFallback string
  for n:=0;n<8;n++{
   part,err:=mr.NextPart()
   if err==io.EOF{break}
   if err!=nil{return "",errors.New("invalid MIME multipart")}
   disposition,_,_:=mime.ParseMediaType(part.Header.Get("Content-Disposition"))
   if disposition=="attachment"{part.Close();continue}
   kind,_,_:=mime.ParseMediaType(part.Header.Get("Content-Type"))
   if kind=="text/plain"||kind=="text/html"{
    value,e:=decodedBody(part,part.Header.Get("Content-Transfer-Encoding"))
    part.Close()
    if e!=nil{continue}
    if kind=="text/plain"{return value,nil}
    htmlFallback=html.UnescapeString(htmlTags.ReplaceAllString(value," "))
   }else{part.Close()}
  }
  if htmlFallback!=""{return htmlFallback,nil}
  return "",errors.New("no text verification body")
 }
 if mediaType!="text/plain"&&mediaType!="text/html"{return "",errors.New("non-text email ignored")}
 result,err:=decodedBody(msg.Body,msg.Header.Get("Content-Transfer-Encoding"))
 if err!=nil{return "",err}
 if mediaType=="text/html"{result=html.UnescapeString(htmlTags.ReplaceAllString(result," "))}
 return result,nil
}
