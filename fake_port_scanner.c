#include <stdio.h>

int main() {
    int open_ports[] = {22, 80, 443, 8080};
    int num_ports = sizeof(open_ports) / sizeof(open_ports[0]);

    printf("Simulating port scan on target 127.0.0.1...\n");
    for (int i = 0; i < num_ports; i++) {
        printf("Port %d is open\n", open_ports[i]);
    }

    printf("Scan complete.\n");
    return 0;
}
