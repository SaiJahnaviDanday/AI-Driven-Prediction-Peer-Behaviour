This project implements an access control mechanism using Solidity smart contracts. It includes tests to ensure the functionality of the contracts.

Installation:

    Node.js and npm:
    Ensure you have Node.js and npm (Node Package Manager) installed on your system. You can download them from the official Node.js website.   

Clone the Repository:
Clone this repository to your local machine using Git:
Bash



Install Dependencies:
Navigate to the project directory and install the required dependencies:
Bash

    cd Access_Control_Mechanism
    npm install

Running the Tests:

Start a Local Ganache Network:
Open a new terminal window and run the following command to start a local Ganache network with 25 accounts:

![alt text](https://github.com/batuhantnrkulu/Access_Control_Mechanism/blob/main/readme1.PNG?raw=true)
Bash

    npx ganache -a 25

Compile and Run Tests:
In another terminal window, navigate to the project directory and run the following command to compile the contracts and execute the tests:
Bash

    truffle test ./test/AccessControlContract.test.js --network development

Additional Notes:

Make sure you have the Truffle framework installed globally. You can install it using npm:
Bash

    npm install -g truffle

If you encounter any issues, refer to the Truffle documentation for troubleshooting and advanced usage.


# 🧠 AI-Driven Prediction of Peer Behavior in Blockchain-Based P2P Networks 

## 📌 Project Overview
This project demonstrates an innovative approach to decentralized access control by integrating block chain 
technology with AI-driven threat detection. Generated dataset from Test cases. We combine three models **XGBoost** using **Random Forest** with **Logistic Regression** to create a flexible, explainable, and high-performance prediction system.


## ⚙️ How to Use

1. 📥 Run the code of Dataset_Simulation.py to generate the dataset.
2. 📓 Use the generated dataset simulated_access_control_dataset.csv as input to the code of Model_Prediction_Behaviour.ipynb.
   👉 Run the code of Model_Prediction_Behaviour.ipynb to obtain the results.
4. 📊 Review the Visulaizations of dataset,feature importance plots and model evaluation metrics to interpret results and assess performance
5. 📝 Check the sample user prediction obtained from the analysis.

---

## 🧠 Technical Stack

- Python (3.10)
- Scikit-learn
- SMOTE
- XGBoost
- Random Forest
- LogisticRegression
- Matplotlib / Seaborn
- RandomizedSearchCV

---

## 📦 Folder Structure

```
AI-predictive-modelling/
│
├── README.md
├── Dataset_Simulation.py
├── simulated_access_control_dataset.csv
├── Model_Prediction_Behaviour.ipynb
└── models/, images/, feature_plots/ (optional)
```

---



