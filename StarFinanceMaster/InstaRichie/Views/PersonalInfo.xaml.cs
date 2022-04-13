// **************************************************************************
//Start Finance - An to manage your personal finances.

//Start Finance is free software: you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation, either version 3 of the License, or
//(at your option) any later version.

//Start Finance is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//GNU General Public License for more details.

//You should have received a copy of the GNU General Public License
//along with Start Finance.If not, see<http://www.gnu.org/licenses/>.
// ***************************************************************************

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
using SQLite;
using StartFinance.Models;
using Windows.UI.Popups;
using SQLite.Net;
using System.Text.RegularExpressions;



namespace StartFinance.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    /// 

    public sealed partial class PersonalInfoPage : Page
    {

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            Results();
        }



        SQLiteConnection conn; // adding an SQLite connection
        string path = Path.Combine(Windows.Storage.ApplicationData.Current.LocalFolder.Path, "Findata.sqlite");

        public PersonalInfoPage()
        {
            this.InitializeComponent();

            NavigationCacheMode = Windows.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
            /// Initializing a database
            conn = new SQLite.Net.SQLiteConnection(new SQLite.Net.Platform.WinRT.SQLitePlatformWinRT(), path);
            // Creating table
            Results();
        }
        public void Results()
        {

            conn.CreateTable<PersonalInfo>();
            var query1 = conn.Table<PersonalInfo>();
            PersonalInfoView.ItemsSource = query1.ToList();
        }



        private async void AddPersonalInfo_Click(object sender, RoutedEventArgs e)
        {
            string FormattedDOB = _DOB.Date.Value.ToString("d");

            try
            {
 
                if ((firstname.Text.ToString() == "") || (_DOB.Date.ToString() == "") || (email.Text.ToString() == ""))
                {
                    MessageDialog dialog = new MessageDialog("Opps...!\nMust enter atleast:\n-First Name\n-DOB\n-Email", "Required Fields Left Blank");
                    await dialog.ShowAsync();
                }
                else
                {
                    // Validate email 
                    Regex validateEmailRegex = new Regex("^\\S+@\\S+\\.\\S+$");
                    if (!validateEmailRegex.IsMatch(email.Text.ToString()))
                    {
                        MessageDialog dialog = new MessageDialog("Opps...!\nYour Email is of Wrong Format", "Invalid Email");
                        await dialog.ShowAsync();
                    }
                    else
                    {
                        conn.CreateTable<PersonalInfo>();
                        conn.Insert(new PersonalInfo
                        {
                            FirstName = firstname.Text.ToString(),
                            LastName = lastname.Text.ToString(),
                            DOB = FormattedDOB,
                            Gender = gender.Text.ToString(),
                            Email = email.Text.ToString(),
                            Mobile = mobile.Text.ToString()

                        });
                        // Creating table
                        Results();
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex is FormatException)
                {
                    MessageDialog dialog = new MessageDialog("There is a Bad Format in some of the Data...", "Please check and try again.");
                    await dialog.ShowAsync();
                }
                else if (ex is SQLiteException)
                {
                    MessageDialog dialog = new MessageDialog("That Record May Already be in the Database", "Check Records");
                    await dialog.ShowAsync();
                }
                else
                {
                    MessageDialog dialog = new MessageDialog("Somthing went wrong", "Oh no..!");
                    await dialog.ShowAsync();
                }
            }
        }

        private async void DeletePersonalInfo_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string AccSelection = ((PersonalInfo)PersonalInfoView.SelectedItem).ID.ToString();

                if (AccSelection == "")
                {
                    MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                    await dialog.ShowAsync();
                }
                else
                {
                    conn.CreateTable<PersonalInfo>();
                    var query1 = conn.Table<PersonalInfo>();
                    var query3 = conn.Query<PersonalInfo>("DELETE FROM PersonalInfo WHERE ID ='" + AccSelection + "'");
                    PersonalInfoView.ItemsSource = query1.ToList();
                }
            }
            catch (NullReferenceException)
            {
                MessageDialog dialog = new MessageDialog("No selected Item", "Oops..!");
                await dialog.ShowAsync();
            }
        }

        private async void EditPersonalInfo_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string FormattedDOB = _DOB.Date.Value.ToString("d");

                string AccSelection = ((PersonalInfo)PersonalInfoView.SelectedItem).ID.ToString();

                if (AccSelection == "")
                {
                    MessageDialog dialog = new MessageDialog("No selected Item", "Oops..!");
                    await dialog.ShowAsync();
                }
                else
                {
                    var tp = conn.Query<PersonalInfo>("UPDATE PersonalInfo SET FirstName = '" + firstname.Text.ToString() + "'," +
                            "LastName = '" + lastname.Text.ToString() + "'," +
                            "DOB = '" + FormattedDOB + "'," +
                            "Gender = '" + gender.Text.ToString() + "'," +
                            "Email = '" + email.Text.ToString() + "'," +
                            "Mobile = '" + mobile.Text.ToString() + "'" +
                            "WHERE ID = '" + AccSelection + "';").FirstOrDefault();
                    // Update Database
                    conn.Update(tp);
                    Results();


                  
                }
            }
            catch (NullReferenceException)
            {
                MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                await dialog.ShowAsync();
            }
        }

        private async void PersonalInfoView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            try
            {
                string AccSelection = ((PersonalInfo)PersonalInfoView.SelectedItem).ID.ToString();
                var query1 = conn.Table<PersonalInfo>();

                string temp = ((PersonalInfo)PersonalInfoView.SelectedItem).DOB.ToString();


                firstname.Text = ((PersonalInfo)PersonalInfoView.SelectedItem).FirstName.ToString();
                lastname.Text = ((PersonalInfo)PersonalInfoView.SelectedItem).LastName.ToString();
                _DOB.Date = DateTimeOffset.Parse(temp);
                gender.Text = ((PersonalInfo)PersonalInfoView.SelectedItem).Gender.ToString();
                email.Text = ((PersonalInfo)PersonalInfoView.SelectedItem).Email.ToString();
                mobile.Text = ((PersonalInfo)PersonalInfoView.SelectedItem).Mobile.ToString();
            }
            catch (Exception ex)
            {
                if (!(ex is NullReferenceException))
                {
                    MessageDialog dialog = new MessageDialog(ex.ToString(), "Oops..!");
                    await dialog.ShowAsync();
                }
              
            }
        }

        private void ClearPersonalInfo_Click(object sender, RoutedEventArgs e)
        {
            firstname.Text = "";
            lastname.Text = "";
            _DOB.Date = null;
            gender.Text = "";
            email.Text = "";            
            mobile.Text = "";
        }


        private void mobile_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private void email_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private void gender_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private void DOB_DateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
        {
        }

        private void lastname_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private void firstname_TextChanged(object sender, TextChangedEventArgs e)
        {
        }

        private void AppBarButton_Click(object sender, RoutedEventArgs e)
        {

        }

      
    }
}
