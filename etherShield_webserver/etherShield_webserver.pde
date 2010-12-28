#include "etherShield.h"
#include <string.h>
// please modify the following two lines. mac and ip have to be unique
// in your local area network. You can not have the same numbers in
// two devices:
static uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x24}; 
static uint8_t myip[4] = {192,168,2,221};
static char baseurl[]="http://192.168.2.221/";
static uint16_t mywwwport =80; // listen port for tcp/www (max range 1-254)
// or on a different port:
//static char baseurl[]="http://10.0.0.24:88/";
//static uint16_t mywwwport =88; // listen port for tcp/www (max range 1-254)
//

#define BUFFER_SIZE 1024
static uint8_t buf[BUFFER_SIZE+1];
#define STR_BUFFER_SIZE 22
static char strbuf[STR_BUFFER_SIZE+1];

const unsigned int STATUS_BREATHE = 0;
const unsigned int STATUS_PARTY   = 1;
const unsigned int STATUS_BLINK   = 2;
const unsigned int STATUS_PING    = 3;

volatile unsigned int nextStatus = STATUS_BREATHE;
long randOn                  = 0;                  // Initialize a variable for the ON time
long randOff                 = 0;                 // Initialize a variable for the OFF time
volatile byte oldRed         = 0xFF;
volatile byte red            = 0xFF;
volatile byte oldGreen       = 0xFF;
volatile byte green          = 0xFF;
volatile byte oldBlue        = 0xFF;
volatile byte blue           = 0xFF;
volatile byte breatheSpeed   = 0xFF;
volatile byte blinkSpeed     = 0xFF;
#define GREEN_PIN 5
#define BLUE_PIN 3
#define RED_PIN 6

char *debugString;

EtherShield es=EtherShield();

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf);
int8_t analyse_cmd(char *str);
void setup(){
  
   /*initialize enc28j60*/
   es.ES_enc28j60Init(mymac);
   es.ES_enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
   es.ES_init_ip_arp_udp_tcp(mymac,myip,80);
   es.ES_enc28j60PhyWrite(EIR, 0);
   es.ES_enc28j60PhyWrite(EIR, EIR_PKTIF);
   attachInterrupt(0, onInterrupt, FALLING);
   pinMode(RED_PIN, OUTPUT);
   pinMode(GREEN_PIN, OUTPUT);
   pinMode(BLUE_PIN, OUTPUT);
        
	/* Magjack leds configuration, see enc28j60 datasheet, page 11 */
	// LEDA=greed LEDB=yellow
	//
	// 0x880 is PHLCON LEDB=on, LEDA=on
	// enc28j60PhyWrite(PHLCON,0b0000 1000 1000 00 00);
	es.ES_enc28j60PhyWrite(PHLCON,0x880);
        digitalWrite(GREEN_PIN, HIGH);
	delay(100);
	//
	// 0x990 is PHLCON LEDB=off, LEDA=off
	// enc28j60PhyWrite(PHLCON,0b0000 1001 1001 00 00);
	es.ES_enc28j60PhyWrite(PHLCON,0x990);
        digitalWrite(GREEN_PIN, LOW);
        digitalWrite(RED_PIN, HIGH);
	delay(100);
	//
	// 0x880 is PHLCON LEDB=on, LEDA=on
	// enc28j60PhyWrite(PHLCON,0b0000 1000 1000 00 00);
	es.ES_enc28j60PhyWrite(PHLCON,0x880);
        digitalWrite(RED_PIN, LOW);
        digitalWrite(BLUE_PIN, HIGH);
	delay(100);
	//
	// 0x990 is PHLCON LEDB=off, LEDA=off
	// enc28j60PhyWrite(PHLCON,0b0000 1001 1001 00 00);
	es.ES_enc28j60PhyWrite(PHLCON,0x990);
        digitalWrite(BLUE_PIN, LOW);
	delay(100);

	//
  // 0x476 is PHLCON LEDA=links status, LEDB=receive/transmit
  // enc28j60PhyWrite(PHLCON,0b0000 0100 0111 01 10);
  es.ES_enc28j60PhyWrite(PHLCON,0x476);
  
  
  Serial.begin(9600);
  Serial.println("hello");
}

void loop(){
  
  //es.ES_enc28j60PhyWrite(EIR, 0);
  //es.ES_enc28j60PhyWrite(EIR, EIR_PKTIF);
  //attachInterrupt(0, onInterrupt, CHANGE);
  //noInterrupts();
  //handlePacket();
  //interrupts();
  delayMicroseconds(100);
  Serial.println("in loop");
  Serial.println(es.ES_get_packet_count(), DEC);
  switch (nextStatus)
  {
    case STATUS_BLINK:
      nextStatus = STATUS_BREATHE;
      blink(red, green, blue, blinkSpeed);
      break;
    case STATUS_BREATHE:
       Serial.println("starting breath");
      breathe(red, green, blue, breatheSpeed);
      //nextStatus = STATUS_BREATHE;
      break;
    case STATUS_PING:
      nextStatus = STATUS_BREATHE;
      digitalWrite(RED_PIN, LOW);
      digitalWrite(BLUE_PIN, LOW);
      digitalWrite(GREEN_PIN, HIGH);
      for (int i = 0; i < 50; i++, delayMicroseconds(10000));
      digitalWrite(GREEN_PIN, LOW);
      for (int i = 0; i < 50; i++, delayMicroseconds(10000));
      break;
    case STATUS_PARTY:
      nextStatus = STATUS_BREATHE;
      party();
      break;
  }
  Serial.println("attaching interrupt");
  attachInterrupt(0, onInterrupt, FALLING);
}
// The returned value is stored in the global var strbuf
uint8_t find_key_val(char *str,char *key)
{
        uint8_t found=0;
        uint8_t i=0;
        char *kp;
        kp=key;
        while(*str &&  *str!=' ' && found==0){
                if (*str == *kp){
                        kp++;
                        if (*kp == '\0'){
                                str++;
                                kp=key;
                                if (*str == '='){
                                        found=1;
                                }
                        }
                }else{
                        kp=key;
                }
                str++;
        }
        if (found==1){
                // copy the value to a buffer and terminate it with '\0'
                while(*str &&  *str!=' ' && *str!='&' && i<STR_BUFFER_SIZE){
                        strbuf[i]=*str;
                        i++;
                        str++;
                }
                strbuf[i]='\0';
        }
        return(found);
}

int8_t analyse_cmd(char *str)
{
        int8_t r=-1;
     
        if (find_key_val(str,"cmd")){
                if (*strbuf < 0x3a && *strbuf > 0x2f){
                        // is a ASCII number, return it
                        r=(*strbuf-0x30);
                }
        }
        return r;
}


uint16_t print_webpage(uint8_t *buf)
{
        uint16_t plen;
     	
        plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<center><p><h1>Welcome to Arduino Ethernet Shield V1.0  </h1></p> "));
       	plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<hr><br> <h2><font color=\"blue\">-- Put your ARDUINO online -- "));
 				plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<br> Control digital outputs "));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("<br> Read digital analog inputs HERE "));
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("  <br></font></h2> ") );
        plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</center><hr>  V1.0 <a href=\"http://www.ekitszone.com\">www.ekitszone.com<a>"));
        //plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</center><hr>  V1.0 <a href=\"http://www.ekitszone.com\">www.ekitszone.com<a>"));
        //plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</center><hr>  V1.0 <a href=\"http://www.ekitszone.com\">www.ekitszone.com<a>"));
        //plen=es.ES_fill_tcp_data_p(buf,plen,PSTR("</center><hr>  V1.0 <a href=\"http://www.ekitszone.com\">www.ekitszone.com<a>"));
//plen=es.ES_fill_tcp_data_p(buf,plen,debugString);
  
        //setBlinkCounter(6);
  
        return(plen);
 }
 
 byte hexToByte(char* hexString) { // accepts a 2-character string with valid hex values
      byte result = 0;
      result |= parseHexChar(hexString[0]) << 4;
      result |= parseHexChar(hexString[1]);
      
      return result;
 }
 
 byte parseHexChar(char c)
 {
      if (c > 47 && c < 58)
      {
        return c - 48;
      } else if (c > 64 && c < 71) {
        return c - 55;
      }
      return 0;
 }
 
void onInterrupt() {
  
  //noInterrupts();
  detachInterrupt(0);
  Serial.println("interrupted");
  while (es.ES_get_packet_count() > 0)
  {
    handlePacket();
  }
  //attachInterrupt(0, onInterrupt, FALLING);
  //interrupts();
  //Serial.println("served interrupt");
}

void handlePacket() {
      
  uint16_t plen, dat_p,backup_dat_p;
  int8_t cmd;
  
  plen = es.ES_enc28j60PacketReceive(BUFFER_SIZE, buf);

	/*plen will ne unequal to zero if there is a valid packet (without crc error) */
  if(plen!=0){
    Serial.println("plen!=0");
	           
    // arp is broadcast if unknown but a host may also verify the mac address by sending it to a unicast address.
    if(es.ES_eth_type_is_arp_and_my_ip(buf,plen)){
      Serial.println("ARP");
      es.ES_make_arp_answer_from_request(buf);
      return;
    }

    // check if ip packets are for us:
    if(es.ES_eth_type_is_ip_and_my_ip(buf,plen)==0){
      Serial.println("not me");
      return;
    }

    if(buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V){
       Serial.println("got ping");
       nextStatus = STATUS_PING;
      es.ES_make_echo_reply_from_request(buf,plen);
      return;
    }
    Serial.println("something else...");
    // tcp port www start, compare only the lower byte
    if (buf[IP_PROTO_P]==IP_PROTO_TCP_V&&buf[TCP_DST_PORT_H_P]==0&&buf[TCP_DST_PORT_L_P]==mywwwport){
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V){
         es.ES_make_tcp_synack_from_syn(buf); // make_tcp_synack_from_syn does already send the syn,ack
         return;     
      }
      if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V){
        es.ES_init_len_info(buf); // init some data structures
        dat_p=es.ES_get_tcp_data_pointer();
        backup_dat_p = dat_p;
        if (dat_p==0){ // we can possibly have no data, just ack:
          if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V){
            es.ES_make_tcp_ack_from_any(buf);
          }
          return;
        }
        if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
          	// head, post and other methods for possible status codes see:
            // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
            plen=es.ES_fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>200 OK</h1>"));
            goto SENDTCP;
        }
        //Serial.print(plen);
        parseCommand(buf,dat_p);
        plen=print_webpage(buf);
        goto SENDTCP;
// 	if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
//          
//          
//         }
//        cmd=analyse_cmd((char *)&(buf[dat_p+5]));
//        if (cmd==1){
//             debugString = (char *)&(buf[dat_p+5]);
//             plen=print_webpage(buf);
//        }
SENDTCP:  es.ES_make_tcp_ack_from_any(buf); // send ack for http get
           es.ES_make_tcp_ack_with_data(buf,plen); // send data       
      }
    }
  } else {
    Serial.println("plen===0");
  }
}
 
void breathe(byte r, byte g, byte b, byte msSpeed) {
  for (byte i = 0; i < 0xFF; i++)
  {
    analogWrite(RED_PIN, map(i, 0, 0xFF, 0, r));
    analogWrite(GREEN_PIN, map(i, 0, 0xFF, 0, g));
    analogWrite(BLUE_PIN, map(i, 0, 0xFF, 0, b));
    delayMicroseconds(msSpeed*7);
  }
  for (byte i = 0xFF; i > 0; i--)
  {
    analogWrite(RED_PIN, map(i, 0, 0xFF, 0, r));
    analogWrite(GREEN_PIN, map(i, 0, 0xFF, 0, g));
    analogWrite(BLUE_PIN, map(i, 0, 0xFF, 0, b));
    delayMicroseconds(msSpeed*7);
  }
} 

void blink(byte r, byte g, byte b, byte msSpeed) {
  for(int i=0;i<10;i++) {
    analogWrite(RED_PIN, r);
    analogWrite(GREEN_PIN, g);
    analogWrite(BLUE_PIN, b);
    for (int i = 0; i < 50; i++, delayMicroseconds(msSpeed*200));
    analogWrite(RED_PIN, 0);
    analogWrite(GREEN_PIN, 0);
    analogWrite(BLUE_PIN, 0);
    for (int i = 0; i < 50; i++, delayMicroseconds(msSpeed*100));
  }
  //for (int i = 0; i < 50; i++, delayMicroseconds(msSpeed*200));  
  green = oldGreen;
  red = oldRed;
  blue = oldBlue;
  nextStatus = STATUS_BREATHE;
}

void party()
{
  
  for(int i=0;i<50;i++) {
     randOn = random (100, 400);    // generate ON time between 0.1 and 1.2 seconds
     randOff = random (30, 100);    // generate OFF time between 0.2 and 0.9 seconds
     green = random(0x00,0xff);
     red   = random(0x00,0xff);
     blue  = random(0x00,0xff);
     analogWrite(RED_PIN, red);
     analogWrite(GREEN_PIN, green);
     analogWrite(BLUE_PIN, blue);
     delay(randOn);
//     analogWrite(RED_PIN, 0);
//     analogWrite(GREEN_PIN, 0);
//     analogWrite(BLUE_PIN, 0);
//     delay(10);
     

  }
  green = oldGreen;
  red = oldRed;
  blue = oldBlue;
  nextStatus = STATUS_BREATHE;
}

uint16_t parseCommand(uint8_t *buf,uint16_t data_start) {
  //All params are a must
  //RGB => CSS hex format
  if(strncmp("/BL",(char *)&(buf[data_start+4]),3)==0) { //BLINK Format:/BL/RRGGBB/Duration(in sec,length:2 chars)
    oldGreen = green;
    oldBlue = blue;
    oldRed = red;
    //sscanf((const char*)&buf[data_start+8],"%2x%2x%2x/%2x",&red,&green,&blue,&blinkSpeed);
    red = hexToByte((char *)&(buf[data_start+8]));
    green = hexToByte((char *)&(buf[data_start+10]));
    blue = hexToByte((char *)&(buf[data_start+12]));
    blinkSpeed = hexToByte((char *)&(buf[data_start+15]));
    nextStatus = STATUS_BLINK;
  } else if (strncmp("/BR",(char *)&(buf[data_start+4]),3)==0) { //BREATH Format:/BR/RRGGBB/Speed(2 Hex char in millisec)
    red = hexToByte((char *)&(buf[data_start+8]));
    green = hexToByte((char *)&(buf[data_start+10]));
    blue = hexToByte((char *)&(buf[data_start+12]));
    breatheSpeed = hexToByte((char *)&(buf[data_start+15]));
    nextStatus = STATUS_BREATHE;
  } else if (strncmp("/PM",(char *)&(buf[data_start+4]),3)==0) { //PartyMode Format :/PM
    nextStatus = STATUS_PARTY;
    oldGreen = green;
    oldBlue = blue;
    oldRed = red;
  } else {
    
  }
}


