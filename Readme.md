### Purpose
Many a times we need to send signals to processes running in background. Like to shutdown a process etc. 
There are many ways to do it. This code is another way to send a Terminate signal to the process.
Issuing a kill -9 is not a viable idea where the graceful exit of the process is required and might cause issues in the next restart of the process.
This software should come in handy at that time.
