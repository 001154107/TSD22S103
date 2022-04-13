using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using SQLite.Net;
using StartFinance.Models;
using Windows.UI.Popups;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=234238

namespace StartFinance.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class ContactDetails : Page
    {
        QLiteConnection conn;  // adding an SQLite connection
        string path = Path.Combine(Windows.Storage.ApplicationData.Current.LocalFolder.Path, "Findata.sqlite");

        public int ContactDetailsId { get; private set; }

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            Results();
        }
        public ContactDetails()
        {

            this.InitializeComponent();

            NavigationCacheMode = Windows.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
            /// Initializing a database
            conn = new SQLiteConnection(new SQLite.Net.Platform.WinRT.SQLitePlatformWinRT(), path);
            // Creating table
            Results();
        }






        private void Results()
        {
            conn.CreateTable<ContactDetails>();
            var query1 = conn.Table<ContactDetails>();
            ContactDetailsList.ItemsSource = query1.ToList();
        }


        private async void AddContactDetails_Click(object sender, RoutedEventArgs e)
        {
            string ContactName1 = ContactName.Text.ToString();
            string DateOfBirth1 = DateOfBirth.Text.ToString();
            string Phone1 = Phone.Text.ToString();
            string Email1 = Email.Text.ToString();
            string Address1 = Address.Text.ToString();
            try
            {
                if ((ContactName1 == "") || (Phone1 == "") || (Address1 == "" || (DateOfBirth1 == "") || (Email1 == ""))
                {
                    MessageDialog dialog = new MessageDialog("Error! Must enter: Contact Name,DateOfBirth, Email, Phone, Address");
                    await dialog.ShowAsync();
                }
                else
                {
                    conn.CreateTable<ContactDetails>();
                    conn.Insert(new ContactDetails
                    {
                        ContactName = ContactName1,
                        DateOfBirth = DateOfBirth1,
                        Phone = Phone1,
                        Email = Email1,
                        Address = Address1
                    });
                    Results();
                }

            }
            catch (Exception ex)
            {
                if (ex is FormatException)
                {
                    MessageDialog dialog = new MessageDialog("There is a wrong format in data", "Error..!");
                    await dialog.ShowAsync();
                }   // Exception handling when SQLite contraints are violated
                else if (ex is SQLiteException)
                {
                    MessageDialog dialog = new MessageDialog("Data already exist, Check record");
                    await dialog.ShowAsync();
                }
                else
                {
                    MessageDialog dialog = new MessageDialog("Something went wrong.");
                    await dialog.ShowAsync();
                }
            }
        }

        private async void DeleteContactDetails_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                int AccSelection = ((ContactDetails)ContactDetailsList.SelectedItem).ContactDetailsId;

                if (AccSelection == 0)
                {
                    MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                    await dialog.ShowAsync();
                }
                else
                {
                    conn.CreateTable<ContactDetails>();
                    var query1 = conn.Table<ContactDetails>();
                    var query3 = conn.Query<ContactDetails>("DELETE FROM ContactDetails WHERE ContactDetailsId ='" + AccSelection + "'");
                    ContactDetailsList.ItemsSource = query1.ToList();
                }
                conn.CreateTable<ContactDetails>();
                var query = conn.Table<ContactDetails>();
                ContactDetailsList.ItemsSource = query.ToList();
            }
            catch (NullReferenceException)
            {
                MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                await dialog.ShowAsync();
            }


        }

        private async void EditContactDetails_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string ContactName1 = ContactName.Text.ToString();
                string DateOfBirth1 = DateOfBirth.Text.ToString();
                string Phone1 = Phone.Text.ToString();
                string Email1 = Email.Text.ToString();
                string Address1 = Address.Text.ToString();

                int AppSelection = ((ContactDetails)ContactDetailsList.SelectedItem).ContactDetailsId;

                if (AppSelection == 0)
                {
                    MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                    await dialog.ShowAsync();
                }
                else
                {
                    var updateQuerry = conn.Query<ContactDetails>("UPDATE ContactDetail SET " +
                        "ContactName = '" + ContactName1 + "'," +
                        "DateOfBirth = '" + DateOfBirth1 + "'," +
                        "Phone = '" + Phone1 + "'," +
                        "Email = '" + Email1 + "'" +
                        "Address = '" + Address1 + "'," +
                        "WHERE ContactDetailId = '" + AppSelection + "';").FirstOrDefault();

                    conn.Update(updateQuerry);
                    Results();

                }

            }
            catch (NullReferenceException)
            {
                MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                await dialog.ShowAsync();
            }


        }

        private void ClearContacDetails_Click(object sender, RoutedEventArgs e)
        {
            ContactName.Text = "";
            DateOfBirth.Text = "";
            Phone.Text = "";
            Email.Text = "";
            Address.Text = "";






        }


    }
}

