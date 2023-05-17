import '../styles/UrlContent.css';
import { useState, useEffect } from 'react'
import Prediction from './Prediction';

function Url({selectedModel}) {
  
    const [link, setlink] = useState("");
    const [isDisplay, setIsDisplay] = useState(false);
    const [getResult, setResult] = useState(false);
    const [data, setdata] = useState({});
    const [id, setid] = useState({});
    const handleSubmit = (event) => {
        event.preventDefault();
        var xmlhttp = new XMLHttpRequest();
        var url = " https://0674-49-237-18-104.ngrok-free.app/api/v01/post/URL/?model="+selectedModel;
        xmlhttp.open("POST", url, true);
        xmlhttp.setRequestHeader("Content-type", "text");
        xmlhttp.setRequestHeader("ngrok-skip-browser-warning","69420")
        xmlhttp.onreadystatechange = function() {//Call a function when the state changes.
            if(xmlhttp.readyState === 4 && xmlhttp.status === 200) {
                setResult(true)
                setid(xmlhttp.responseText)
            }
          }
        
        xmlhttp.send(link);
    }

    useEffect(() => {
      if(getResult === true && isDisplay===false){
        fetch('  https://0674-49-237-18-104.ngrok-free.app/api/v01/get/resURL/?id='+id, {
          method: "get",
          headers: new Headers({
            "ngrok-skip-browser-warning": "69420",
          }),
        })
        .then(response => {
            return response.json(); // <<- Return the JSON Object
        })
        .then(result => {
          setdata(result);
          setIsDisplay(true);
        })
        .catch(error => { // Use .catch() to catch exceptions. Either in the request or any of your .then() blocks
            console.error(error); // Log the error object in the console.
            const errorMessage = 'Something went wrong';
            console.log(errorMessage);
        });
      }
  },[selectedModel,getResult,isDisplay,id]);

  return getResult ? (
    <Prediction selectedModel={selectedModel} isDisplay={isDisplay} setIsDisplay={setIsDisplay} data={data} />
  )  :  (
    <div className="UrlContent">
        
        <form className='Form' onSubmit={handleSubmit}>
      <label>Entrer le titre ou l'URL : 
        <input 
          className='inpute'
          type="text" 
          value={link}
          onChange={(e) => setlink(e.target.value)}
        />
      </label>
      <input type="submit" className='Button'/>
    </form>
    </div>
  );
}

export default Url;
