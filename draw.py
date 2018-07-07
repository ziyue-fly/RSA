import numpy as np
import matplotlib.pyplot as plt

en = np.loadtxt('enTime.txt')
de = np.loadtxt('deTime.txt')
x = en[:,1]
y = en[:,0]
z = de[:,0]



plt.scatter(x, y, s = 0.5, c = 'blue', label = 'Encrypt Time')
plt.scatter(x, z, s = 0.5, c = 'red', label = 'Decrypt Time')
plt.xlabel('Test cases')
plt.ylabel('Time/ms')
plt.legend()
plt.title('Encrypt Time and Decrypt Time in 10000 test cases')
plt.show()
