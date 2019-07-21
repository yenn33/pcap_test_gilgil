#include <pcap.h>
#include <stdio.h>

void print_mac(const u_char* mac){
   printf("%02x:%02x:%02x:%02x:%02x:%02x  ", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip){
   printf("%d.%d.%d.%d  ", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char* packet){
   printf("%d  ", (packet[0] * 16 * 16) + (packet[1]));
}

void print_data(const u_char* data){
    printf("\"data : %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\"  ", data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],data[9]);
}


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }


  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  int i = 0;
  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    i++;

    u_char IHL = packet[14]&0x0F;
    IHL = IHL * 4;

    u_char Offset = packet[IHL+26]&0xF0;
    Offset = Offset >> 4;
    Offset = Offset * 4;

    bpf_u_int32 caplen = header->caplen;
    int Datalen = caplen - 14 - IHL - Offset;


    printf("%u bytes captured  ", header->caplen);
    print_mac(&packet[0]);
    print_mac(&packet[6]);

    if (packet[12]==0x08 && packet[13]==0x00){
        print_ip(&packet[26]);
        print_ip(&packet[30]);

        if(packet[23]==0x06){
            print_port(&packet[IHL+14]);
            print_port(&packet[IHL+16]);
            //print_data(&packet[14+IHL+Offset]);


            printf("data: ");
            for(int i=0 ; i<Datalen && i<=9 ; i++){
                printf("%02x ", packet[14+IHL+Offset+i]);
            }


        }

    }
    printf("\n");

  }

  pcap_close(handle);
  return 0;
}
