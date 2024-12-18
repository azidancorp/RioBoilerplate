import pandas as pd
import numpy as np
from datetime import datetime

def generate_sales_data():
    # Generate weekly dates for the year 2023
    weeks = pd.date_range(start='2023-01-01', end='2023-12-31', freq='W')
    num_weeks = len(weeks)

    # Seed for reproducibility
    np.random.seed(42)

    # Generate synthetic sales data
    online_sales = np.cumsum(np.random.randint(50, 200, num_weeks)) + 1000
    in_store_sales = np.cumsum(np.random.randint(30, 150, num_weeks)) + 800
    total_sales = online_sales + in_store_sales

    # Create a DataFrame for the sales data
    sales_data = pd.DataFrame({
        'Week': weeks,
        'Online Sales': online_sales,
        'In-Store Sales': in_store_sales,
        'Total Sales': total_sales
    })

    return sales_data

if __name__ == "__main__":
    sales_data = generate_sales_data()
    # Save to CSV in the `data` folder
    # Adjust the path as needed depending on your project structure
    sales_data.to_csv('../data/sales_data.csv', index=False)
    print("sales_data.csv generated successfully!")
