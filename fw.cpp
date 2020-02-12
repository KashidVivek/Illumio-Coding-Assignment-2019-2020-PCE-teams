
#include<iostream>
#include<vector>
#include <fstream>
#include <sstream>  
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
using namespace std;

//Firewall Rules
struct rule{
public:
	rule(string direction,string protocol,string port,string ip_addr){
		this->direction = direction;
		this->protocol = protocol;
		this->port = port;
		this->ip_addr = ip_addr;
	}
	string direction;
	string protocol;
	string port;
	string ip_addr;
};


//Firewall class 
class firewall{
public:
	string path;
	vector<rule*>fw_rules;
	void get_rules();
	bool accept_packet(string direction, string protocol, int port, string ip_addr);
	bool check_port(string c_port, int port);
	bool check_ip_addr(string c_ip_addr, string ip_addr);
	string ipToHexa(string addr);
	firewall(string path){
		this->path = path;
	}

};

//Function to parse csv file
void firewall :: get_rules(){
	ifstream ip(path);
	string direction,protocol,port,ip_addr,is;
	while(ip.good()){
		getline(ip,direction,',');
		getline(ip,protocol,',');
		getline(ip,port,',');
		getline(ip,ip_addr,'\n');
		rule *R = new rule(direction,protocol,port,ip_addr);
		fw_rules.push_back(R);
	}

}

//Function to return true or false for allowing packet
bool firewall :: accept_packet(string direction, string protocol, int port, string ip_addr){
	for(auto i=fw_rules.begin();i != fw_rules.end();i++){
		if(((*i)->direction == direction) && ((*i)->protocol == protocol) && check_port((*i)->port,port) && check_ip_addr((*i)->ip_addr,ip_addr)){
			return true;
		}
	}
	return false;
}


//Function to check port ranges
bool firewall :: check_port(string c_port, int port){
	stringstream ss(c_port);
	string l_val,r_val;
	if(c_port.size()==2){
		getline(ss,l_val);
		int l = stoi(l_val);
		if(l == port)
			return true;
	}
	else{
		getline(ss,l_val,'-');
		getline(ss,r_val,'-');
		int l = stoi(l_val);
		int r = stoi(r_val);
		if(l <= port && r >= port)
			return true;
	}
	return false;
}


//Function to check IP in the range is valid 
bool firewall :: check_ip_addr(string c_ip_addr,string ip_addr){
	stringstream ss(c_ip_addr);
	string l_val,r_val;
	if(c_ip_addr.size()<=15){
		getline(ss,l_val);
		cout<<l_val;
		if(l_val == ip_addr){
			cout<<"Matched";
			return true;
		}
	}
	else{
		getline(ss,l_val,'-');
		getline(ss,r_val,'-');
		string l = ipToHexa(l_val);
		string r = ipToHexa(r_val);
		string addr = ipToHexa(ip_addr);
		if(l< addr && r >= addr){
		 	return true;
		}
	}
	return false;
}
 

// Function to conversion and print 
// the hexadecimal value 
string firewall :: ipToHexa(string addr) 
{ 
	stringstream  data(addr);
	string ip="0x";
    string line;
    while(getline(data,line,'.'))
    {
    	int i = stoi(line);
    	stringstream sstr;
    	sstr << std::hex << i;
    	ip += sstr.str();
    }
    cout<<ip<<endl;
    return ip;
}

int main(){
	firewall *f = new firewall("/Users/vivek/Desktop/Illumio Coding Assignment/input.csv");
	f->get_rules();
	cout<< std::boolalpha<<f->accept_packet("outbound", "tcp", 10234,"192.168.10.11")<<endl;
	cout<< std::boolalpha<<f->accept_packet("inbound", "udp", 53, "192.168.2.1")<<endl;
	return 0;
}
